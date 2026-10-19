"""Nexus data models.

Trust boundary (the whole point of the design):

  ProposalRequest  -> UNTRUSTED. Comes from the LLM agent. Carries an offer_id, never a price.
  SignedOffer      -> UNTRUSTED until its signature is verified by catalog.OfferResolver.
  ResolvedOffer    -> TRUSTED. Built only by the gateway from a verified offer. The policy engine
                      and the PayPal order are built from THIS, never from agent text.
  Warrant          -> TRUSTED. Created by the human, immutable.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from decimal import ROUND_HALF_UP, Decimal
from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

CENT = Decimal("0.01")


# ---------------------------------------------------------------- money helpers (never floats)
def q2(d: Decimal) -> Decimal:
    return d.quantize(CENT, rounding=ROUND_HALF_UP)


def to_cents(d: Decimal) -> int:
    return int(q2(d) * 100)


def from_cents(c: int) -> Decimal:
    return q2(Decimal(c) / 100)


def canonical_json(obj: Any) -> str:
    """Deterministic JSON. Merchant signer and gateway verifier MUST share this exact function."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


Money = Annotated[Decimal, Field(ge=Decimal("0"), max_digits=9, decimal_places=2)]
IdStr = Annotated[str, Field(pattern=r"^[A-Za-z0-9_\-]{6,64}$")]


# ---------------------------------------------------------------- enums
class Category(str, Enum):
    """Closed taxonomy owned by the catalog. The LLM never gets to invent a category."""
    ELECTRONICS = "electronics"
    BOOKS = "books"
    GROCERY = "grocery"
    GIFT_CARDS = "gift_cards"
    OTHER = "other"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    ESCALATE = "ESCALATE"
    DENY = "DENY"


class ReasonCode(str, Enum):
    OK = "OK"
    ESCALATE_OVER_THRESHOLD = "ESCALATE_OVER_THRESHOLD"
    DENY_MALFORMED_PROPOSAL = "DENY_MALFORMED_PROPOSAL"
    DENY_OFFER_UNRESOLVED = "DENY_OFFER_UNRESOLVED"
    DENY_OFFER_SIGNATURE = "DENY_OFFER_SIGNATURE"
    DENY_OFFER_EXPIRED = "DENY_OFFER_EXPIRED"
    DENY_PAYEE_NOT_ALLOWED = "DENY_PAYEE_NOT_ALLOWED"
    DENY_WARRANT_INACTIVE = "DENY_WARRANT_INACTIVE"
    DENY_WARRANT_EXPIRED = "DENY_WARRANT_EXPIRED"
    DENY_CURRENCY = "DENY_CURRENCY"
    DENY_MERCHANT_NOT_ALLOWED = "DENY_MERCHANT_NOT_ALLOWED"
    DENY_CATEGORY_NOT_ALLOWED = "DENY_CATEGORY_NOT_ALLOWED"
    DENY_EXCEEDS_PER_TXN = "DENY_EXCEEDS_PER_TXN"
    DENY_EXCEEDS_BUDGET = "DENY_EXCEEDS_BUDGET"
    DENY_VELOCITY = "DENY_VELOCITY"
    DENY_IDEMPOTENCY_CONFLICT = "DENY_IDEMPOTENCY_CONFLICT"
    DENY_PAYPAL_ERROR = "DENY_PAYPAL_ERROR"
    DENY_PAYPAL_MISMATCH = "DENY_PAYPAL_MISMATCH"
    DENY_APPROVAL_INVALID = "DENY_APPROVAL_INVALID"
    DENY_REJECTED_BY_HUMAN = "DENY_REJECTED_BY_HUMAN"
    DENY_PRICE_TAMPERING = "DENY_PRICE_TAMPERING"
    DENY_PAYEE_MISMATCH = "DENY_PAYEE_MISMATCH"
    PAYPAL_UNCERTAIN = "PAYPAL_UNCERTAIN"


# ---------------------------------------------------------------- UNTRUSTED: agent input
class ProposalRequest(BaseModel):
    """What the agent is allowed to say. Note what is missing: price, merchant, category.

    extra='forbid' means an agent that tries to smuggle in `amount`, `category` or `merchant`
    fails validation, and the gateway logs the attempt (see Gateway.reject_malformed).
    """
    model_config = ConfigDict(extra="forbid", frozen=True)

    offer_id: IdStr
    quantity: Annotated[int, Field(ge=1, le=10)] = 1
    idempotency_key: IdStr
    rationale: Annotated[str, Field(max_length=500)] = ""  # logged as untrusted text, NEVER evaluated


# ---------------------------------------------------------------- merchant/catalog offer
class OfferPayload(BaseModel):
    """The facts the merchant/catalog asserts. Signed as a unit."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    offer_id: IdStr
    merchant_id: str = Field(min_length=1, max_length=64)
    payee_merchant_id: str = Field(min_length=1, max_length=64)  # PayPal merchant id that must receive funds
    sku: str = Field(min_length=1, max_length=64)
    title: str = Field(min_length=1, max_length=127)
    category: Category
    unit_price: Money
    currency: Literal["USD"]
    shipping: Money = Decimal("0.00")
    tax_rate: Annotated[Decimal, Field(ge=Decimal("0"), le=Decimal("0.5"), max_digits=5, decimal_places=4)] = Decimal("0")
    valid_until: datetime

    @field_validator("unit_price", "shipping")
    @classmethod
    def _norm_money(cls, v: Decimal) -> Decimal:
        return q2(v)

    @field_validator("tax_rate")
    @classmethod
    def _norm_rate(cls, v: Decimal) -> Decimal:
        return v.quantize(Decimal("0.0001"))

    @field_validator("valid_until")
    @classmethod
    def _utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("valid_until must be timezone-aware")
        return v.astimezone(timezone.utc)

    def canonical(self) -> str:
        return canonical_json(self.model_dump(mode="json"))


class SignedOffer(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    payload: OfferPayload
    # HMAC (64) ki jagah ab Ed25519 (128 chars) use hoga
    signature: str = Field(min_length=128, max_length=128)


# ---------------------------------------------------------------- TRUSTED: gateway-computed truth
class ResolvedOffer(BaseModel):
    """Every number the policy engine and PayPal will ever see. Computed here, with Decimal."""
    model_config = ConfigDict(frozen=True)

    offer: OfferPayload
    quantity: int
    item_total: Decimal
    shipping: Decimal
    tax: Decimal
    total: Decimal
    total_cents: int
    offer_hash: str  # binds (verified payload + quantity); what a human approves, what a receipt cites

    @classmethod
    def build(cls, payload: OfferPayload, quantity: int) -> "ResolvedOffer":
        item_total = q2(payload.unit_price * quantity)
        tax = q2(item_total * payload.tax_rate)
        total = q2(item_total + payload.shipping + tax)
        h = sha256_hex(canonical_json({"offer": payload.model_dump(mode="json"), "quantity": quantity}))
        return cls(offer=payload, quantity=quantity, item_total=item_total, shipping=payload.shipping,
                   tax=tax, total=total, total_cents=to_cents(total), offer_hash=h)


class Warrant(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    warrant_id: IdStr
    currency: Literal["USD"] = "USD"
    budget_total: Money           # cumulative cap across the warrant's life
    max_per_txn: Money
    approval_threshold: Money     # total above this => ESCALATE (hold funds, ask a human)
    allowed_categories: frozenset[Category]
    allowed_merchants: frozenset[str]
    max_txn_per_hour: Annotated[int, Field(ge=1, le=1000)] = 10
    not_before: datetime
    expires_at: datetime
    vault_id: str = Field(repr=False)  # PayPal payment token. Never leaves the gateway process.


# ---------------------------------------------------------------- decision trace (append-only)
class TraceStep(BaseModel):
    rule: str                      # e.g. "policy.category"
    passed: bool
    code: ReasonCode
    facts: dict[str, str | int | bool | None] = Field(default_factory=dict)  # values compared, as strings


class ResolvedSummary(BaseModel):
    offer_id: str
    merchant_id: str
    payee_merchant_id: str
    sku: str
    title: str
    category: Category
    quantity: int
    item_total: str
    shipping: str
    tax: str
    total: str
    offer_hash: str

    @classmethod
    def of(cls, r: ResolvedOffer) -> "ResolvedSummary":
        o = r.offer
        return cls(offer_id=o.offer_id, merchant_id=o.merchant_id, payee_merchant_id=o.payee_merchant_id,
                   sku=o.sku, title=o.title, category=o.category, quantity=r.quantity,
                   item_total=str(r.item_total), shipping=str(r.shipping), tax=str(r.tax),
                   total=str(r.total), offer_hash=r.offer_hash)


class DecisionTrace(BaseModel):
    """One record per proposal. `agent_claim` is what the agent SAID (untrusted);
    `resolved` is what the gateway independently established (trusted). Dashboards show both side by side."""
    trace_id: str
    created_at: datetime
    warrant_id: str
    idempotency_key: str
    agent_claim: dict[str, str]
    resolved: ResolvedSummary | None
    steps: list[TraceStep]
    decision: Decision
    final_code: ReasonCode
    reservation_id: str | None = None


class LifecycleEvent(BaseModel):
    """PayPal-side facts after the decision: order created, authorized, captured, voided..."""
    reservation_id: str
    event: Literal["AUTHORIZED", "CAPTURED", "APPROVED", "REJECTED", "VOIDED", "RELEASED", "UNCERTAIN"]
    code: ReasonCode = ReasonCode.OK
    paypal: dict[str, str | None] = Field(default_factory=dict)
    facts: dict[str, str | int | bool | None] = Field(default_factory=dict)
    at: datetime


# ---------------------------------------------------------------- API responses
class ApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    offer_hash: str = Field(min_length=64, max_length=64)  # the human approves THIS exact offer


class GatewayResponse(BaseModel):
    """Everything the agent (and the user-facing reply) may say about the outcome.
    Generate the user message from this object, never from free LLM text."""
    status: Literal["CAPTURED", "PENDING_APPROVAL", "DENIED", "VOIDED", "UNCERTAIN"]
    decision: Decision
    code: ReasonCode
    message: str
    trace_id: str | None = None
    reservation_id: str | None = None
    total: Decimal | None = None
    offer_hash: str | None = None
