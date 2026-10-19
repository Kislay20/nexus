"""SQLite reservation ledger.

Double-spend prevention = ONE rule: every check-and-consume of budget happens inside a single
`BEGIN IMMEDIATE` transaction. SQLite allows only one writer at a time, so two concurrent
reserve() calls are serialized; the second one sees the first one's row and is denied.

Money is stored as integer cents. Budget is held from the moment a reservation is created
(RESERVED) through PayPal authorization (AUTHORIZED) and capture (CAPTURED). Only RELEASED and
VOIDED give budget back. UNCERTAIN (network ambiguity) keeps holding budget until reconciled.

Use from FastAPI via asyncio.to_thread (sqlite3 is blocking). One connection per transaction
keeps it thread-safe; WAL + busy_timeout make writers queue instead of erroring.
"""
from __future__ import annotations

import hashlib
import secrets
import sqlite3
import uuid
import os
from cryptography.hazmat.primitives.asymmetric import ed25519
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator

from pydantic import BaseModel

from .models import ReasonCode, ResolvedOffer, Warrant, canonical_json, sha256_hex, to_cents

ACTIVE_STATES = ("RESERVED", "AUTHORIZED", "CAPTURED", "UNCERTAIN")
_ALLOWED: dict[str, set[str]] = {
    "RESERVED": {"AUTHORIZED", "RELEASED", "UNCERTAIN"},
    "AUTHORIZED": {"CAPTURED", "VOIDED", "UNCERTAIN"},
    "UNCERTAIN": {"AUTHORIZED", "CAPTURED", "VOIDED", "RELEASED"},  # resolved by reconciliation
}
_PAYPAL_COLS = {"paypal_order_id", "paypal_authorization_id", "paypal_capture_id"}
GENESIS = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS warrants (
  warrant_id TEXT PRIMARY KEY,
  body       TEXT NOT NULL,                 -- immutable Warrant JSON
  revoked    INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS agent_tokens (
  token_hash TEXT PRIMARY KEY,              -- sha256(token); the agent holds the token, we hold the hash
  warrant_id TEXT NOT NULL REFERENCES warrants(warrant_id)
);
CREATE TABLE IF NOT EXISTS reservations (
  reservation_id          TEXT PRIMARY KEY,
  warrant_id              TEXT NOT NULL REFERENCES warrants(warrant_id),
  idempotency_key         TEXT NOT NULL,
  offer_hash              TEXT NOT NULL,
  amount_cents            INTEGER NOT NULL CHECK (amount_cents > 0),
  state                   TEXT NOT NULL CHECK (state IN
                          ('RESERVED','AUTHORIZED','CAPTURED','RELEASED','VOIDED','UNCERTAIN')),
  needs_approval          INTEGER NOT NULL DEFAULT 0,
  paypal_order_id         TEXT,
  paypal_authorization_id TEXT,
  paypal_capture_id       TEXT,
  created_at              TEXT NOT NULL,
  updated_at              TEXT NOT NULL,
  UNIQUE (warrant_id, idempotency_key)      -- replay of the same proposal can never create a 2nd row
);
CREATE INDEX IF NOT EXISTS idx_resv_warrant_state ON reservations(warrant_id, state);
CREATE TABLE IF NOT EXISTS trace_log (
  seq            INTEGER PRIMARY KEY AUTOINCREMENT,
  kind           TEXT NOT NULL,             -- DECISION | LIFECYCLE
  reservation_id TEXT,
  body           TEXT NOT NULL,             -- canonical JSON
  prev_hash      TEXT NOT NULL,
  hash           TEXT NOT NULL,             -- sha256(prev_hash || body)
  created_at     TEXT NOT NULL
);
-- ==========================================
-- WEBAUTHN / PASSKEYS SCHEMA
-- ==========================================
CREATE TABLE IF NOT EXISTS approvers (
  id TEXT PRIMARY KEY,
  label TEXT NOT NULL,
  user_handle BLOB NOT NULL UNIQUE,   -- random 32 bytes, never PII
  created_at TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS webauthn_credentials (
  credential_id BLOB PRIMARY KEY,
  approver_id TEXT NOT NULL REFERENCES approvers(id),
  public_key_cose BLOB NOT NULL,      -- what py_webauthn verifies with
  public_key_pem TEXT NOT NULL,       -- so nexus_verify needs no CBOR
  sign_count INTEGER NOT NULL DEFAULT 0,
  transports TEXT,
  aaguid TEXT,
  created_at TEXT NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS webauthn_challenges (
  id TEXT PRIMARY KEY,
  purpose TEXT NOT NULL CHECK (purpose IN ('register', 'approve')),
  reservation_id TEXT,
  challenge BLOB NOT NULL,
  preimage_json TEXT,                 -- the exact canonical JSON that was hashed
  expires_at TEXT NOT NULL,
  consumed_at TEXT
);

CREATE TABLE IF NOT EXISTS approval_links (
  reservation_id TEXT PRIMARY KEY,
  token_hash BLOB NOT NULL,           -- sha256 of a random 128-bit link token
  expires_at TEXT NOT NULL
);
"""


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


class Reservation(BaseModel):
    reservation_id: str
    warrant_id: str
    idempotency_key: str
    offer_hash: str
    amount_cents: int
    state: str
    needs_approval: bool
    paypal_order_id: str | None = None
    paypal_authorization_id: str | None = None
    paypal_capture_id: str | None = None
    created_at: str

    @classmethod
    def from_row(cls, row: sqlite3.Row) -> "Reservation":
        return cls(**{k: row[k] for k in cls.model_fields})


class ReserveResult(BaseModel):
    ok: bool
    code: ReasonCode
    replay: bool = False
    reservation: Reservation | None = None
    budget_cents: int = 0
    committed_before_cents: int = 0
    remaining_after_cents: int = 0
    recent_count: int = 0


class Ledger:
    def __init__(self, path: str):
        self.path = path
        cx = sqlite3.connect(path, timeout=10)
        cx.execute("PRAGMA journal_mode=WAL")
        cx.executescript(SCHEMA)
        
        # Safe migration: Add signature column if it doesn't exist
        try:
            cx.execute("ALTER TABLE trace_log ADD COLUMN signature TEXT NOT NULL DEFAULT ''")
        except sqlite3.OperationalError:
            pass # Column already exists

        cx.commit()
        cx.close()

        # Load Ed25519 keys from .env
        priv_hex = os.environ.get("LEDGER_PRIVATE_KEY", "")
        pub_hex = os.environ.get("LEDGER_PUBLIC_KEY", "")
        self._priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex)) if priv_hex else None
        self._pub_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex)) if pub_hex else None

    # ------------------------------------------------------------ connection / transaction
    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        cx = sqlite3.connect(self.path, timeout=10, isolation_level=None)  # autocommit; we manage BEGIN
        cx.row_factory = sqlite3.Row
        cx.execute("PRAGMA busy_timeout=10000")
        cx.execute("PRAGMA foreign_keys=ON")
        try:
            cx.execute("BEGIN IMMEDIATE")  # take the write lock NOW, before reading anything
            yield cx
            cx.execute("COMMIT")
        except BaseException:
            try:
                cx.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            raise
        finally:
            cx.close()

    # ------------------------------------------------------------ warrants & agent tokens
    def put_warrant(self, w: Warrant) -> None:
        with self._tx() as cx:
            cx.execute("INSERT INTO warrants(warrant_id, body) VALUES (?, ?)", (w.warrant_id, w.model_dump_json()))

    def get_warrant(self, warrant_id: str) -> tuple[Warrant, bool] | None:
        with self._tx() as cx:
            row = cx.execute("SELECT body, revoked FROM warrants WHERE warrant_id=?", (warrant_id,)).fetchone()
        return (Warrant.model_validate_json(row["body"]), bool(row["revoked"])) if row else None

    def revoke_warrant(self, warrant_id: str) -> None:
        with self._tx() as cx:
            cx.execute("UPDATE warrants SET revoked=1 WHERE warrant_id=?", (warrant_id,))

    def issue_agent_token(self, warrant_id: str) -> str:
        token = secrets.token_urlsafe(32)
        with self._tx() as cx:
            cx.execute("INSERT INTO agent_tokens(token_hash, warrant_id) VALUES (?, ?)",
                       (hashlib.sha256(token.encode()).hexdigest(), warrant_id))
        return token

    def warrant_for_token(self, token: str) -> str | None:
        with self._tx() as cx:
            row = cx.execute("SELECT warrant_id FROM agent_tokens WHERE token_hash=?",
                             (hashlib.sha256(token.encode()).hexdigest(),)).fetchone()
        return row["warrant_id"] if row else None

    # ------------------------------------------------------------ THE critical section
    def reserve(self, warrant: Warrant, offer: ResolvedOffer, idempotency_key: str, now: datetime) -> ReserveResult:
        """Atomically: replay check -> cumulative budget check -> velocity check -> insert.

        Because this runs under BEGIN IMMEDIATE, "read committed total, compare, insert" cannot
        interleave with another reserve() on the same database. That is the double-spend guard.
        """
        budget = to_cents(warrant.budget_total)
        amount = offer.total_cents
        with self._tx() as cx:
            # (a) Idempotent replay: same (warrant, key) returns the original row, never a second charge.
            row = cx.execute("SELECT * FROM reservations WHERE warrant_id=? AND idempotency_key=?",
                             (warrant.warrant_id, idempotency_key)).fetchone()
            if row:
                existing = Reservation.from_row(row)
                if existing.offer_hash != offer.offer_hash:  # same key, different goods => attack or bug
                    return ReserveResult(ok=False, code=ReasonCode.DENY_IDEMPOTENCY_CONFLICT, budget_cents=budget)
                return ReserveResult(ok=True, code=ReasonCode.OK, replay=True, reservation=existing, budget_cents=budget)

            # (b) Cumulative budget across ALL budget-holding states.
            marks = ",".join("?" * len(ACTIVE_STATES))
            committed = cx.execute(
                f"SELECT COALESCE(SUM(amount_cents),0) AS s FROM reservations WHERE warrant_id=? AND state IN ({marks})",
                (warrant.warrant_id, *ACTIVE_STATES)).fetchone()["s"]
            if committed + amount > budget:
                return ReserveResult(ok=False, code=ReasonCode.DENY_EXCEEDS_BUDGET, budget_cents=budget,
                                     committed_before_cents=committed, remaining_after_cents=budget - committed)

            # (c) Velocity: attempts that reached the ledger in the last hour (any state).
            since = iso(now - timedelta(hours=1))
            recent = cx.execute("SELECT COUNT(*) AS c FROM reservations WHERE warrant_id=? AND created_at>=?",
                                (warrant.warrant_id, since)).fetchone()["c"]
            if recent >= warrant.max_txn_per_hour:
                return ReserveResult(ok=False, code=ReasonCode.DENY_VELOCITY, budget_cents=budget,
                                     committed_before_cents=committed, remaining_after_cents=budget - committed,
                                     recent_count=recent)

            # (d) Consume the budget in the SAME transaction.
            rid = "rsv_" + uuid.uuid4().hex[:24]
            ts = iso(now)
            cx.execute(
                "INSERT INTO reservations(reservation_id, warrant_id, idempotency_key, offer_hash, amount_cents,"
                " state, created_at, updated_at) VALUES (?,?,?,?,?,'RESERVED',?,?)",
                (rid, warrant.warrant_id, idempotency_key, offer.offer_hash, amount, ts, ts))
            created = Reservation.from_row(cx.execute("SELECT * FROM reservations WHERE reservation_id=?", (rid,)).fetchone())
            return ReserveResult(ok=True, code=ReasonCode.OK, reservation=created, budget_cents=budget,
                                 committed_before_cents=committed, remaining_after_cents=budget - committed - amount,
                                 recent_count=recent)

    # ------------------------------------------------------------ state machine (compare-and-set)
    def transition(self, reservation_id: str, *, expect: tuple[str, ...], to: str, now: datetime,
                   **paypal_ids: str | None) -> bool:
        """Move state only if it is currently one of `expect`. Returns False if someone else got there first."""
        assert all(to in _ALLOWED.get(e, set()) for e in expect), f"illegal transition {expect}->{to}"
        assert set(paypal_ids) <= _PAYPAL_COLS, "unknown column"
        sets = "".join(f", {k}=?" for k in paypal_ids)
        marks = ",".join("?" * len(expect))
        with self._tx() as cx:
            cur = cx.execute(
                f"UPDATE reservations SET state=?, updated_at=?{sets} WHERE reservation_id=? AND state IN ({marks})",
                (to, iso(now), *paypal_ids.values(), reservation_id, *expect))
            return cur.rowcount == 1

    def mark_needs_approval(self, reservation_id: str) -> None:
        with self._tx() as cx:
            cx.execute("UPDATE reservations SET needs_approval=1 WHERE reservation_id=? AND state='AUTHORIZED'",
                       (reservation_id,))

    def claim_approval(self, reservation_id: str, offer_hash: str) -> bool:
        """Atomically consume a pending approval. Double-clicks / replays get False => no 2nd capture."""
        with self._tx() as cx:
            cur = cx.execute(
                "UPDATE reservations SET needs_approval=0 "
                "WHERE reservation_id=? AND state='AUTHORIZED' AND needs_approval=1 AND offer_hash=?",
                (reservation_id, offer_hash))
            return cur.rowcount == 1

    def get_reservation(self, reservation_id: str) -> Reservation | None:
        with self._tx() as cx:
            row = cx.execute("SELECT * FROM reservations WHERE reservation_id=?", (reservation_id,)).fetchone()
        return Reservation.from_row(row) if row else None

    def committed_cents(self, warrant_id: str) -> int:
        marks = ",".join("?" * len(ACTIVE_STATES))
        with self._tx() as cx:
            return cx.execute(
                f"SELECT COALESCE(SUM(amount_cents),0) AS s FROM reservations WHERE warrant_id=? AND state IN ({marks})",
                (warrant_id, *ACTIVE_STATES)).fetchone()["s"]

    # ------------------------------------------------------------ hash-chained audit log
    def append_trace(self, kind: str, reservation_id: str | None, body: dict[str, Any], now: datetime) -> str:
        payload = canonical_json(body)
        with self._tx() as cx:
            last = cx.execute("SELECT hash FROM trace_log ORDER BY seq DESC LIMIT 1").fetchone()
            prev = last["hash"] if last else GENESIS
            h = sha256_hex(prev + payload)
            
            # Sign the hash using our external private key
            sig = self._priv_key.sign(h.encode('utf-8')).hex() if self._priv_key else ""
            
            cx.execute("INSERT INTO trace_log(kind, reservation_id, body, prev_hash, hash, signature, created_at) VALUES (?,?,?,?,?,?,?)",
                       (kind, reservation_id, payload, prev, h, sig, iso(now)))
            return h

    def verify_chain(self) -> tuple[bool, int | None]:
        """(True, None) if intact; else (False, seq_of_first_bad_row). Checks hashes AND cryptographic signatures."""
        prev = GENESIS
        with self._tx() as cx:
            for row in cx.execute("SELECT seq, body, prev_hash, hash, signature FROM trace_log ORDER BY seq"):
                # 1. Verify Hash Chain
                if row["prev_hash"] != prev or sha256_hex(prev + row["body"]) != row["hash"]:
                    return False, row["seq"]
                
                # 2. Verify External Signature (prevents DB-rewrite attacks)
                if self._pub_key and row["signature"]:
                    try:
                        self._pub_key.verify(bytes.fromhex(row["signature"]), row["hash"].encode('utf-8'))
                    except Exception:
                        return False, row["seq"]
                
                prev = row["hash"]
        return True, None

    def traces_after(self, seq: int = 0, limit: int = 100) -> list[dict[str, Any]]:
        import json
        with self._tx() as cx:
            rows = cx.execute("SELECT seq, kind, reservation_id, body, hash, created_at FROM trace_log "
                              "WHERE seq>? ORDER BY seq LIMIT ?", (seq, limit)).fetchall()
        return [{"seq": r["seq"], "kind": r["kind"], "reservation_id": r["reservation_id"],
                 "body": json.loads(r["body"]), "hash": r["hash"], "created_at": r["created_at"]} for r in rows]

    # =========================================================================
    # WEBAUTHN / PASSKEYS LOGIC
    # =========================================================================
    
    def get_or_create_approver(self, label: str) -> sqlite3.Row:
        with self._tx() as cx:
            row = cx.execute("SELECT * FROM approvers WHERE label=?", (label,)).fetchone()
            if not row:
                aid = "app_" + secrets.token_hex(8)
                user_handle = secrets.token_bytes(32)
                now_str = iso(datetime.now(timezone.utc))
                cx.execute("INSERT INTO approvers(id, label, user_handle, created_at) VALUES (?,?,?,?)",
                           (aid, label, user_handle, now_str))
                row = cx.execute("SELECT * FROM approvers WHERE id=?", (aid,)).fetchone()
            return row

    def save_challenge(self, purpose: str, challenge: bytes, ttl_seconds: int, preimage_json: str = None, rid: str = None) -> str:
        cid = "chl_" + secrets.token_hex(12)
        exp = iso(datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds))
        with self._tx() as cx:
            cx.execute("INSERT INTO webauthn_challenges(id, purpose, reservation_id, challenge, preimage_json, expires_at) VALUES (?,?,?,?,?,?)",
                       (cid, purpose, rid, challenge, preimage_json, exp))
        return cid

    def live_challenge(self, rid: str | None, purpose: str) -> sqlite3.Row | None:
        now_str = iso(datetime.now(timezone.utc))
        query = "SELECT * FROM webauthn_challenges WHERE purpose=? AND expires_at>? AND consumed_at IS NULL"
        params = [purpose, now_str]
        if rid:
            query += " AND reservation_id=?"
            params.append(rid)
        query += " ORDER BY expires_at DESC LIMIT 1"
        with self._tx() as cx:
            return cx.execute(query, tuple(params)).fetchone()

    def consume_challenge(self, challenge_id: str) -> None:
        with self._tx() as cx:
            cx.execute("UPDATE webauthn_challenges SET consumed_at=? WHERE id=?", 
                       (iso(datetime.now(timezone.utc)), challenge_id))

    def export_audit_bundle(self) -> dict[str, Any]:
        """Export the complete cryptographic audit trail with public key and signatures for offline verification."""
        pub_hex = os.environ.get("LEDGER_PUBLIC_KEY", "")
        with self._tx() as cx:
            rows = [
                dict(r) for r in cx.execute(
                    "SELECT seq, kind, reservation_id, body, prev_hash, hash, signature, created_at "
                    "FROM trace_log ORDER BY seq"
                ).fetchall()
            ]
        return {
            "version": "1.0",
            "exported_at": iso(datetime.now(timezone.utc)),
            "ledger_public_key": pub_hex,
            "total_blocks": len(rows),
            "chain": rows,
        }

