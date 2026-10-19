from __future__ import annotations

import sqlite3
import threading
from decimal import Decimal

from conftest import NOW, make_offer, make_warrant
from nexus.ledger import Ledger
from nexus.models import ReasonCode, ResolvedOffer, to_cents


def resolved(price: str = "60.00", offer_id: str = "offer_mouse_60") -> ResolvedOffer:
    return ResolvedOffer.build(make_offer(offer_id, price=price), 1)


def test_concurrent_reserves_cannot_double_spend(tmp_path):
    """20 threads each try to reserve $60 against a $100 budget. Exactly ONE may win."""
    ledger = Ledger(str(tmp_path / "l.db"))
    w = make_warrant(max_txn_per_hour=100)
    ledger.put_warrant(w)
    results, barrier = [], threading.Barrier(20)

    def worker(i: int) -> None:
        barrier.wait()  # release all threads at once to maximize contention
        results.append(ledger.reserve(w, resolved(), f"key_{i:04d}_xx", NOW))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
    [t.start() for t in threads]
    [t.join() for t in threads]

    assert sum(r.ok for r in results) == 1
    assert sum(r.code == ReasonCode.DENY_EXCEEDS_BUDGET for r in results) == 19
    assert ledger.committed_cents(w.warrant_id) == 6000 <= to_cents(w.budget_total)  # the invariant


def test_splitting_attack_is_bounded_by_cumulative_budget(tmp_path):
    """Five $30 purchases (each under any per-txn cap) cannot exceed the $100 budget."""
    ledger = Ledger(str(tmp_path / "l.db"))
    w = make_warrant(max_per_txn=Decimal("40.00"))
    ledger.put_warrant(w)
    oks = [ledger.reserve(w, resolved("30.00", f"offer_split_{i}"), f"split_key_{i}", NOW).ok for i in range(5)]
    assert oks == [True, True, True, False, False]
    assert ledger.committed_cents(w.warrant_id) == 9000


def test_idempotent_replay_returns_same_row_and_does_not_consume_budget(tmp_path):
    ledger = Ledger(str(tmp_path / "l.db"))
    w = make_warrant()
    ledger.put_warrant(w)
    a = ledger.reserve(w, resolved(), "same_key_01", NOW)
    b = ledger.reserve(w, resolved(), "same_key_01", NOW)
    assert a.ok and b.ok and b.replay
    assert a.reservation.reservation_id == b.reservation.reservation_id
    assert ledger.committed_cents(w.warrant_id) == 6000


def test_same_key_different_goods_is_a_conflict(tmp_path):
    ledger = Ledger(str(tmp_path / "l.db"))
    w = make_warrant()
    ledger.put_warrant(w)
    assert ledger.reserve(w, resolved("10.00", "offer_cheap_1"), "reused_key_1", NOW).ok
    r = ledger.reserve(w, resolved("20.00", "offer_other_2"), "reused_key_1", NOW)
    assert not r.ok and r.code == ReasonCode.DENY_IDEMPOTENCY_CONFLICT


def test_velocity_limit(tmp_path):
    ledger = Ledger(str(tmp_path / "l.db"))
    w = make_warrant(max_txn_per_hour=2, budget_total=Decimal("100.00"))
    ledger.put_warrant(w)
    codes = [ledger.reserve(w, resolved("1.00", f"offer_tiny_{i}"), f"vel_key_{i}", NOW).code for i in range(3)]
    assert codes == [ReasonCode.OK, ReasonCode.OK, ReasonCode.DENY_VELOCITY]


def test_released_and_voided_return_budget_but_uncertain_keeps_holding_it(tmp_path):
    ledger = Ledger(str(tmp_path / "l.db"))
    w = make_warrant()
    ledger.put_warrant(w)
    r1 = ledger.reserve(w, resolved("40.00", "offer_a_00001"), "k_release_1", NOW).reservation
    r2 = ledger.reserve(w, resolved("40.00", "offer_b_00001"), "k_uncertn_1", NOW).reservation
    assert ledger.committed_cents(w.warrant_id) == 8000
    assert ledger.transition(r1.reservation_id, expect=("RESERVED",), to="RELEASED", now=NOW)
    assert ledger.transition(r2.reservation_id, expect=("RESERVED",), to="UNCERTAIN", now=NOW)
    assert ledger.committed_cents(w.warrant_id) == 4000  # only the UNCERTAIN one still holds budget


def test_state_transition_is_compare_and_set(tmp_path):
    ledger = Ledger(str(tmp_path / "l.db"))
    w = make_warrant()
    ledger.put_warrant(w)
    r = ledger.reserve(w, resolved(), "cas_key_001", NOW).reservation
    assert ledger.transition(r.reservation_id, expect=("RESERVED",), to="AUTHORIZED", now=NOW, paypal_authorization_id="A1")
    # second actor with a stale view loses the race
    assert not ledger.transition(r.reservation_id, expect=("RESERVED",), to="AUTHORIZED", now=NOW)


def test_claim_approval_is_single_use(tmp_path):
    ledger = Ledger(str(tmp_path / "l.db"))
    w = make_warrant()
    ledger.put_warrant(w)
    r = ledger.reserve(w, resolved(), "appr_key_01", NOW).reservation
    ledger.transition(r.reservation_id, expect=("RESERVED",), to="AUTHORIZED", now=NOW)
    ledger.mark_needs_approval(r.reservation_id)
    assert not ledger.claim_approval(r.reservation_id, "0" * 64)       # wrong offer_hash
    assert ledger.claim_approval(r.reservation_id, r.offer_hash)       # first approval wins
    assert not ledger.claim_approval(r.reservation_id, r.offer_hash)   # double-click / replay loses


def test_audit_chain_detects_tampering(tmp_path):
    path = str(tmp_path / "l.db")
    ledger = Ledger(path)
    for i in range(3):
        ledger.append_trace("DECISION", None, {"n": i, "decision": "DENY"}, NOW)
    assert ledger.verify_chain() == (True, None)
    cx = sqlite3.connect(path)  # attacker edits history
    cx.execute("UPDATE trace_log SET body = REPLACE(body, 'DENY', 'ALLOW') WHERE seq = 2")
    cx.commit()
    cx.close()
    assert ledger.verify_chain() == (False, 2)
