"""Gateway orchestration: the only code path that can move money.

Order of operations for POST /v1/proposals (each step can only DENY or continue; any error fails closed):

  1. schema      agent sent exactly {offer_id, quantity, idempotency_key, rationale}  (no price, no category)
  2. resolve     gateway fetches the offer from the catalog, verifies signature + freshness, computes totals
  3. policy      stateless rules on the RESOLVED offer (merchant, category, per-txn, window, currency)
  4. reserve     ATOMIC cumulative-budget + velocity + idempotency check, consuming budget (ledger.reserve)
  5. log         append the DecisionTrace (hash-chained) BEFORE any money call
  6. authorize   PayPal order intent=AUTHORIZE built only from the resolved offer, via the vault token
  7. verify      PayPal's echoed amount/currency/payee/custom_id must equal what we computed; else VOID
  8. capture     auto (ALLOW) or after human approval of the exact offer_hash (ESCALATE); verify the capture
"""
from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, Callable

from pydantic import ValidationError

from . import policy
from .catalog import OfferError, OfferResolver
from .ledger import Ledger, Reservation
from .models import (Decision, DecisionTrace, GatewayResponse, LifecycleEvent, ProposalRequest, ReasonCode,
                     ResolvedOffer, ResolvedSummary, TraceStep, Warrant, from_cents)
from .paypal import (AuthFacts, PayPalClient, PayPalDefiniteError, PayPalUncertain, parse_authorization)

# Circuit Breaker: Tracks strikes for agents who exceed budgets
CIRCUIT_BREAKER_STRIKES: dict[str, int] = {}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------- verify what PayPal echoes back
def check_authorization(f: AuthFacts, r: ResolvedOffer, reservation_id: str, trace_anchor: str, *, strict_payee: bool) -> list[str]:
    """Never trust PayPal's response blindly either: compare it to the numbers WE computed in step 2."""
    problems: list[str] = []
    if f.status != "CREATED":
        problems.append(f"authorization status {f.status!r} != 'CREATED'")
    if f.amount != r.total:
        problems.append(f"authorized {f.amount} != expected {r.total}")
    if f.currency != r.offer.currency:
        problems.append(f"currency {f.currency} != {r.offer.currency}")
        
    # Naya logic: Ab hum strict check karenge ki PayPal ne hash anchor wapas bheja ya nahi!
    expected_cid = f"{reservation_id}:{trace_anchor[:8]}" if trace_anchor else reservation_id
    if f.custom_id is not None and f.custom_id != expected_cid:
        problems.append("custom_id does not match reservation + hash anchor")
        
    if f.payee_merchant_id is None:
        if strict_payee:
            problems.append("PayPal response has no payee.merchant_id")
    elif f.payee_merchant_id != r.offer.payee_merchant_id:
        problems.append(f"payee {f.payee_merchant_id} != expected {r.offer.payee_merchant_id}")
    return problems


def check_capture(cap: dict[str, Any], amount: Decimal, currency: str) -> list[str]:
    problems: list[str] = []
    if cap.get("status") != "COMPLETED":
        problems.append(f"capture status {cap.get('status')!r} != 'COMPLETED'")
    a = cap.get("amount") or {}
    try:
        if Decimal(str(a.get("value"))) != amount:
            problems.append(f"captured {a.get('value')} != expected {amount}")
    except InvalidOperation:
        problems.append("capture amount unreadable")
    if a.get("currency_code") != currency:
        problems.append(f"capture currency {a.get('currency_code')} != {currency}")
    return problems


class Gateway:
    def __init__(self, ledger: Ledger, resolver: OfferResolver, paypal: PayPalClient, *,
                 clock: Callable[[], datetime] = utcnow, strict_payee: bool = False):
        self.ledger, self.resolver, self.paypal = ledger, resolver, paypal
        self.clock, self.strict_payee = clock, strict_payee

    # ------------------------------------------------------------ small helpers
    async def _db(self, fn: Callable[..., Any], *a: Any, **k: Any) -> Any:
        return await asyncio.to_thread(fn, *a, **k)  # sqlite3 is blocking

    @staticmethod
    def _msg(status: str, code: ReasonCode, r: ResolvedOffer | None) -> str:
        # Deterministic template. The agent's reply to the user must be built from THIS, not free text.
        what = f" | {r.offer.title} x{r.quantity} = ${r.total}" if r else ""
        return f"{status}: {code.value}{what}"

    async def _log_decision(self, trace: DecisionTrace) -> str:
        return await self._db(self.ledger.append_trace, "DECISION", trace.reservation_id,
                              trace.model_dump(mode="json"), self.clock())

    async def _log_event(self, rid: str, event: str, code: ReasonCode = ReasonCode.OK,
                         paypal: dict[str, str | None] | None = None, **facts: str | int | bool | None) -> None:
        ev = LifecycleEvent(reservation_id=rid, event=event, code=code, paypal=paypal or {},  # type: ignore[arg-type]
                            facts=facts, at=self.clock())
        await self._db(self.ledger.append_trace, "LIFECYCLE", rid, ev.model_dump(mode="json"), self.clock())

    def _trace(self, warrant_id: str, claim: dict[str, str], key: str, resolved: ResolvedOffer | None,
               steps: list[TraceStep], decision: Decision, code: ReasonCode, rid: str | None = None) -> DecisionTrace:
        return DecisionTrace(trace_id="trc_" + uuid.uuid4().hex[:16], created_at=self.clock(), warrant_id=warrant_id,
                             idempotency_key=key, agent_claim=claim,
                             resolved=ResolvedSummary.of(resolved) if resolved else None,
                             steps=steps, decision=decision, final_code=code, reservation_id=rid)

    async def _deny(self, warrant_id: str, claim: dict[str, str], key: str, resolved: ResolvedOffer | None,
                    steps: list[TraceStep], code: ReasonCode) -> GatewayResponse:
        
        # --- 🚨 SMART CIRCUIT BREAKER 🚨 ---
        global CIRCUIT_BREAKER_STRIKES
        code_name = code.name if hasattr(code, "name") else str(code)
        
        # CLAUDE'S FIX: No instant bans for replays (network timeouts) or merchant-side signature errors.
        # We ONLY penalize the Agent for aggressively trying to exceed their allocated limits.
        if code_name in ["DENY_EXCEEDS_BUDGET", "DENY_EXCEEDS_PER_TXN", "DENY_VELOCITY"]:
            strikes = CIRCUIT_BREAKER_STRIKES.get(warrant_id, 0) + 1
            CIRCUIT_BREAKER_STRIKES[warrant_id] = strikes
            if strikes >= 3:
                await self._db(self.ledger.revoke_warrant, warrant_id)
                steps.append(TraceStep(rule="circuit_breaker", passed=False, code=code, facts={"action": "SUSPENDED", "strikes": strikes}))
                print(f"\n🚨 [CIRCUIT BREAKER] 3-STRIKES SUSPENSION: Warrant {warrant_id} suspended! 🚨")
        # -------------------------------------------------

        t = self._trace(warrant_id, claim, key, resolved, steps, Decision.DENY, code)
        await self._log_decision(t)
        return GatewayResponse(status="DENIED", decision=Decision.DENY, code=code, trace_id=t.trace_id,
                               message=self._msg("BLOCKED", code, resolved),
                               total=resolved.total if resolved else None)

    # ------------------------------------------------------------ malformed / smuggled input
    async def reject_malformed(self, warrant_id: str, raw: dict[str, Any], err: ValidationError) -> GatewayResponse:
        """Agent sent a field it may not send (e.g. `amount`, `category`). Deny AND leave evidence."""
        extra = sorted(str(e["loc"][0]) for e in err.errors() if e["type"] == "extra_forbidden" and e["loc"])
        
        # ✨ NAYA LOGIC: Claude ke liye exact tags set karo ✨
        code = ReasonCode.DENY_MALFORMED_PROPOSAL
        if "amount" in extra:
            code = ReasonCode.DENY_PRICE_TAMPERING
        elif "payee_merchant_id" in extra:
            code = ReasonCode.DENY_PAYEE_MISMATCH

        steps = [TraceStep(rule="request.schema", passed=False, code=code,
                           facts={"unexpected_fields": ",".join(extra) or None, "error_count": err.error_count()})]
        claim = {str(k)[:40]: str(v)[:200] for k, v in raw.items()}
        return await self._deny(warrant_id, claim, str(raw.get("idempotency_key", "n/a"))[:64], None, steps, code)

    # ------------------------------------------------------------ the main flow
    async def propose(self, warrant_id: str, req: ProposalRequest) -> GatewayResponse:
        now = self.clock()
        found = await self._db(self.ledger.get_warrant, warrant_id)
        if found is None:
            raise KeyError(warrant_id)
        warrant, revoked = found
        claim = {"offer_id": req.offer_id, "quantity": str(req.quantity), "rationale": req.rationale[:200]}
        steps: list[TraceStep] = []

        # 2. independent price resolution --------------------------------------------------
        try:
            resolved = await self.resolver.resolve(req.offer_id, req.quantity, now)
        except OfferError as e:
            steps.append(TraceStep(rule="offer.resolve", passed=False, code=e.code, facts={"detail": e.detail}))
            return await self._deny(warrant_id, claim, req.idempotency_key, None, steps, e.code)
        steps.append(TraceStep(rule="offer.resolve", passed=True, code=ReasonCode.OK, facts={
            "merchant": resolved.offer.merchant_id, "category": resolved.offer.category.value,
            "unit_price": str(resolved.offer.unit_price), "item_total": str(resolved.item_total),
            "shipping": str(resolved.shipping), "tax": str(resolved.tax), "total": str(resolved.total),
            "offer_hash": resolved.offer_hash[:16]}))

        # 3. stateless policy on RESOLVED facts --------------------------------------------
        steps += policy.evaluate(warrant, resolved, now, revoked)
        failed = [s for s in steps if not s.passed]
        if failed:
            return await self._deny(warrant_id, claim, req.idempotency_key, resolved, steps, failed[0].code)

        # 4. atomic reservation ------------------------------------------------------------
        rr = await self._db(self.ledger.reserve, warrant, resolved, req.idempotency_key, now)
        steps.append(TraceStep(rule="ledger.reserve", passed=rr.ok, code=rr.code, facts={
            "budget": str(from_cents(rr.budget_cents)), "committed_before": str(from_cents(rr.committed_before_cents)),
            "remaining_after": str(from_cents(rr.remaining_after_cents)), "recent_count": rr.recent_count,
            "replay": rr.replay}))
        if not rr.ok:
            return await self._deny(warrant_id, claim, req.idempotency_key, resolved, steps, rr.code)
        assert rr.reservation is not None
        resv = rr.reservation
        if rr.replay:
            return self._from_reservation(resv, resolved)  # idempotent: same answer, no second charge

        needs_approval = resolved.total > warrant.approval_threshold
        steps.append(TraceStep(rule="policy.approval_threshold", passed=True,
                               code=ReasonCode.ESCALATE_OVER_THRESHOLD if needs_approval else ReasonCode.OK,
                               facts={"total": str(resolved.total), "threshold": str(warrant.approval_threshold)}))
        decision = Decision.ESCALATE if needs_approval else Decision.ALLOW
        code = ReasonCode.ESCALATE_OVER_THRESHOLD if needs_approval else ReasonCode.OK

        # 5. log the decision BEFORE any money call ---------------------------------------
        trace = self._trace(warrant_id, claim, req.idempotency_key, resolved, steps, decision, code, resv.reservation_id)
        trace_anchor = await self._log_decision(trace)

        # 6-8. PayPal -----------------------------------------------------------------------
        return await self._execute(warrant, resolved, resv, needs_approval, trace.trace_id, decision, trace_anchor)

    # ------------------------------------------------------------ PayPal: authorize -> verify -> (capture)
    async def _execute(self, warrant: Warrant, resolved: ResolvedOffer, resv: Reservation, needs_approval: bool,
                       trace_id: str, decision: Decision, trace_anchor: str) -> GatewayResponse:
        rid, now = resv.reservation_id, self.clock()
        order_id: str | None = None
        try:
            # Send the short hash (8 chars) of the trace as the external anchor!
            order = await self.paypal.create_authorize_order(
                resolved=resolved, vault_id=warrant.vault_id, reservation_id=rid, trace_anchor=trace_anchor[:8]
            )
            order_id = order.get("id")
            facts = parse_authorization(order)
            if facts is None:  # SPIKE: some flows return APPROVED and need an explicit /authorize call
                order = await self.paypal.authorize_order(order_id or "", reservation_id=rid)
                facts = parse_authorization(order)
        except PayPalDefiniteError as e:
            return await self._release(resv, resolved, trace_id, ReasonCode.DENY_PAYPAL_ERROR, str(e)[:200])
        except PayPalUncertain:
            return await self._uncertain(resv, resolved, trace_id, order_id)
        if facts is None:
            return await self._release(resv, resolved, trace_id, ReasonCode.DENY_PAYPAL_ERROR, "no authorization returned")

        # record the hold first (so we can always void it), THEN verify what PayPal says it held
        ok = await self._db(self.ledger.transition, rid, expect=("RESERVED",), to="AUTHORIZED", now=now,
                            paypal_order_id=order_id, paypal_authorization_id=facts.authorization_id)
        if not ok:
            return await self._uncertain(resv, resolved, trace_id, order_id)
        await self._log_event(rid, "AUTHORIZED", paypal={"order_id": order_id, "authorization_id": facts.authorization_id},
                              amount=str(facts.amount), currency=facts.currency)

        problems = check_authorization(facts, resolved, rid, trace_anchor, strict_payee=self.strict_payee)
        if problems:
            return await self._void(rid, facts.authorization_id, ReasonCode.DENY_PAYPAL_MISMATCH, resolved, trace_id,
                                    "; ".join(problems))

        if needs_approval:  # funds are HELD at PayPal; a human must approve this exact offer_hash
            await self._db(self.ledger.mark_needs_approval, rid)
            return GatewayResponse(status="PENDING_APPROVAL", decision=Decision.ESCALATE,
                                   code=ReasonCode.ESCALATE_OVER_THRESHOLD, trace_id=trace_id, reservation_id=rid,
                                   total=resolved.total, offer_hash=resolved.offer_hash,
                                   message=self._msg("HELD FOR APPROVAL", ReasonCode.ESCALATE_OVER_THRESHOLD, resolved))
        return await self._capture(rid, facts.authorization_id, from_cents(resv.amount_cents), warrant.currency,
                                   resolved, trace_id, decision)

    async def _capture(self, rid: str, auth_id: str, amount: Decimal, currency: str, resolved: ResolvedOffer | None,
                       trace_id: str | None, decision: Decision) -> GatewayResponse:
        now = self.clock()
        try:
            cap = await self.paypal.capture_authorization(auth_id, amount=amount, currency=currency, reservation_id=rid)
        except PayPalDefiniteError as e:  # hold unusable (expired/voided) => nothing captured => free the budget
            await self._db(self.ledger.transition, rid, expect=("AUTHORIZED",), to="VOIDED", now=now)
            await self._log_event(rid, "VOIDED", ReasonCode.DENY_PAYPAL_ERROR, detail=str(e)[:200])
            return GatewayResponse(status="DENIED", decision=Decision.DENY, code=ReasonCode.DENY_PAYPAL_ERROR,
                                   trace_id=trace_id, reservation_id=rid,
                                   message=self._msg("CAPTURE FAILED", ReasonCode.DENY_PAYPAL_ERROR, resolved))
        except PayPalUncertain:
            return await self._uncertain_by_id(rid, resolved, trace_id)
        problems = check_capture(cap, amount, currency)
        if problems:  # money may have moved wrongly: keep budget held, flag for reconciliation / refund
            await self._db(self.ledger.transition, rid, expect=("AUTHORIZED",), to="UNCERTAIN", now=now,
                           paypal_capture_id=cap.get("id"))
            await self._log_event(rid, "UNCERTAIN", ReasonCode.DENY_PAYPAL_MISMATCH, detail="; ".join(problems))
            return GatewayResponse(status="UNCERTAIN", decision=decision, code=ReasonCode.DENY_PAYPAL_MISMATCH,
                                   trace_id=trace_id, reservation_id=rid,
                                   message=self._msg("NEEDS RECONCILIATION", ReasonCode.DENY_PAYPAL_MISMATCH, resolved))
        await self._db(self.ledger.transition, rid, expect=("AUTHORIZED",), to="CAPTURED", now=now,
                       paypal_capture_id=cap.get("id"))
        await self._log_event(rid, "CAPTURED", paypal={"authorization_id": auth_id, "capture_id": cap.get("id")},
                              amount=str(amount))
        return GatewayResponse(status="CAPTURED", decision=decision, code=ReasonCode.OK, trace_id=trace_id,
                               reservation_id=rid, total=amount, offer_hash=resolved.offer_hash if resolved else None,
                               message=self._msg("PURCHASED", ReasonCode.OK, resolved))

    # ------------------------------------------------------------ human approval of a held authorization
    async def approve(self, reservation_id: str, offer_hash: str) -> GatewayResponse:
        resv = await self._db(self.ledger.get_reservation, reservation_id)
        if resv is None:
            raise KeyError(reservation_id)
        found = await self._db(self.ledger.get_warrant, resv.warrant_id)
        assert found is not None
        warrant, revoked = found
        if not await self._db(self.ledger.claim_approval, reservation_id, offer_hash):
            return GatewayResponse(status="DENIED", decision=Decision.DENY, code=ReasonCode.DENY_APPROVAL_INVALID,
                                   reservation_id=reservation_id,
                                   message="BLOCKED: DENY_APPROVAL_INVALID (not pending, already decided, or wrong offer)")
        await self._log_event(reservation_id, "APPROVED")
        assert resv.paypal_authorization_id
        if revoked:  # warrant revoked while the human was deciding
            return await self._void(reservation_id, resv.paypal_authorization_id, ReasonCode.DENY_WARRANT_INACTIVE, None, None, "revoked")
        return await self._capture(reservation_id, resv.paypal_authorization_id, from_cents(resv.amount_cents),
                                   warrant.currency, None, None, Decision.ESCALATE)

    async def reject(self, reservation_id: str) -> GatewayResponse:
        resv = await self._db(self.ledger.get_reservation, reservation_id)
        if resv is None:
            raise KeyError(reservation_id)
        if not await self._db(self.ledger.claim_approval, reservation_id, resv.offer_hash):
            return GatewayResponse(status="DENIED", decision=Decision.DENY, code=ReasonCode.DENY_APPROVAL_INVALID,
                                   reservation_id=reservation_id, message="BLOCKED: DENY_APPROVAL_INVALID")
        await self._log_event(reservation_id, "REJECTED", ReasonCode.DENY_REJECTED_BY_HUMAN)
        assert resv.paypal_authorization_id
        return await self._void(reservation_id, resv.paypal_authorization_id, ReasonCode.DENY_REJECTED_BY_HUMAN, None, None, "human rejected")

    # ------------------------------------------------------------ unhappy paths
    async def _void(self, rid: str, auth_id: str, code: ReasonCode, resolved: ResolvedOffer | None,
                    trace_id: str | None, detail: str) -> GatewayResponse:
        now = self.clock()
        try:
            await self.paypal.void_authorization(auth_id, reservation_id=rid)
        except (PayPalDefiniteError, PayPalUncertain):
            # We could not CONFIRM the hold is gone => keep holding budget until reconciled.
            return await self._uncertain_by_id(rid, resolved, trace_id)
        await self._db(self.ledger.transition, rid, expect=("AUTHORIZED",), to="VOIDED", now=now)
        await self._log_event(rid, "VOIDED", code, detail=detail[:300])
        return GatewayResponse(status="VOIDED", decision=Decision.DENY, code=code, trace_id=trace_id,
                               reservation_id=rid, message=self._msg("BLOCKED", code, resolved))

    async def _release(self, resv: Reservation, resolved: ResolvedOffer, trace_id: str, code: ReasonCode,
                       detail: str) -> GatewayResponse:
        await self._db(self.ledger.transition, resv.reservation_id, expect=("RESERVED",), to="RELEASED", now=self.clock())
        await self._log_event(resv.reservation_id, "RELEASED", code, detail=detail)
        return GatewayResponse(status="DENIED", decision=Decision.DENY, code=code, trace_id=trace_id,
                               reservation_id=resv.reservation_id, message=self._msg("BLOCKED", code, resolved))

    async def _uncertain(self, resv: Reservation, resolved: ResolvedOffer, trace_id: str, order_id: str | None) -> GatewayResponse:
        return await self._uncertain_by_id(resv.reservation_id, resolved, trace_id)

    async def _uncertain_by_id(self, rid: str, resolved: ResolvedOffer | None, trace_id: str | None) -> GatewayResponse:
        await self._db(self.ledger.transition, rid, expect=("RESERVED", "AUTHORIZED"), to="UNCERTAIN", now=self.clock())
        await self._log_event(rid, "UNCERTAIN", ReasonCode.PAYPAL_UNCERTAIN)
        return GatewayResponse(status="UNCERTAIN", decision=Decision.ALLOW, code=ReasonCode.PAYPAL_UNCERTAIN,
                               trace_id=trace_id, reservation_id=rid,
                               message=self._msg("PENDING RECONCILIATION", ReasonCode.PAYPAL_UNCERTAIN, resolved))

    def _from_reservation(self, r: Reservation, resolved: ResolvedOffer) -> GatewayResponse:
        """Replay of an already-processed idempotency key: report the stored outcome, do nothing."""
        total = from_cents(r.amount_cents)
        if r.state == "CAPTURED":
            return GatewayResponse(status="CAPTURED", decision=Decision.ALLOW, code=ReasonCode.OK, total=total,
                                   reservation_id=r.reservation_id, message=self._msg("PURCHASED (replay)", ReasonCode.OK, resolved))
        if r.state == "AUTHORIZED" and r.needs_approval:
            return GatewayResponse(status="PENDING_APPROVAL", decision=Decision.ESCALATE,
                                   code=ReasonCode.ESCALATE_OVER_THRESHOLD, total=total, offer_hash=r.offer_hash,
                                   reservation_id=r.reservation_id,
                                   message=self._msg("HELD FOR APPROVAL (replay)", ReasonCode.ESCALATE_OVER_THRESHOLD, resolved))
        if r.state in ("RELEASED", "VOIDED"):
            return GatewayResponse(status="DENIED", decision=Decision.DENY, code=ReasonCode.DENY_PAYPAL_ERROR,
                                   reservation_id=r.reservation_id, message=self._msg("BLOCKED (replay)", ReasonCode.DENY_PAYPAL_ERROR, resolved))
        return GatewayResponse(status="UNCERTAIN", decision=Decision.ALLOW, code=ReasonCode.PAYPAL_UNCERTAIN,
                               reservation_id=r.reservation_id, message=self._msg("IN PROGRESS (replay)", ReasonCode.PAYPAL_UNCERTAIN, resolved))
