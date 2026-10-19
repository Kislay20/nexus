"""Stateless, deterministic policy rules. Pure function: same inputs -> same trace. No LLM, no I/O.

Stateful rules (cumulative budget, velocity) live in ledger.reserve() because they must be
evaluated atomically with the write that consumes the budget.
"""
from __future__ import annotations

from datetime import datetime

from .models import ReasonCode, ResolvedOffer, TraceStep, Warrant


def _step(rule: str, ok: bool, fail_code: ReasonCode, **facts: str | int | bool | None) -> TraceStep:
    return TraceStep(rule=rule, passed=ok, code=ReasonCode.OK if ok else fail_code, facts=facts)


def evaluate(w: Warrant, r: ResolvedOffer, now: datetime, revoked: bool) -> list[TraceStep]:
    """Evaluate ALL rules (no short-circuit) so the trace shows every reason a request failed."""
    o = r.offer
    return [
        _step("warrant.active", not revoked, ReasonCode.DENY_WARRANT_INACTIVE, revoked=revoked),
        _step("warrant.window", w.not_before <= now < w.expires_at, ReasonCode.DENY_WARRANT_EXPIRED,
              not_before=w.not_before.isoformat(), expires_at=w.expires_at.isoformat()),
        _step("offer.currency", o.currency == w.currency, ReasonCode.DENY_CURRENCY,
              offer=o.currency, warrant=w.currency),
        _step("policy.merchant", o.merchant_id in w.allowed_merchants, ReasonCode.DENY_MERCHANT_NOT_ALLOWED,
              merchant=o.merchant_id),
        _step("policy.category", o.category in w.allowed_categories, ReasonCode.DENY_CATEGORY_NOT_ALLOWED,
              category=o.category.value),
        _step("policy.per_txn", r.total <= w.max_per_txn, ReasonCode.DENY_EXCEEDS_PER_TXN,
              total=str(r.total), max=str(w.max_per_txn)),
    ]
