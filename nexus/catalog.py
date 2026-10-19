"""Independent price verification.

The agent sends an offer_id. The gateway fetches the offer ITSELF from the catalog/merchant,
verifies the merchant's signature, checks freshness, and computes every amount with Decimal.
Nothing the agent wrote ever reaches the policy engine or PayPal.
"""
from __future__ import annotations

import binascii
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

import hmac
from datetime import datetime
from typing import Any, Mapping, Protocol

import httpx
from pydantic import ValidationError

from .models import OfferPayload, ReasonCode, ResolvedOffer, SignedOffer


class OfferError(Exception):
    def __init__(self, code: ReasonCode, detail: str = ""):
        super().__init__(f"{code.value}: {detail}")
        self.code = code
        self.detail = detail


class CatalogClient(Protocol):
    async def fetch(self, offer_id: str) -> dict[str, Any] | None: ...


class HttpCatalogClient:
    """Calls the merchant/catalog service over a channel the agent has no access to."""

    def __init__(self, base_url: str, *, transport: httpx.AsyncBaseTransport | None = None, timeout: float = 3.0):
        self._http = httpx.AsyncClient(base_url=base_url, transport=transport, timeout=timeout)

    async def fetch(self, offer_id: str) -> dict[str, Any] | None:
        r = await self._http.get(f"/offers/{offer_id}")
        if r.status_code == 404:
            return None
        r.raise_for_status()
        return r.json()


def sign_offer(payload: OfferPayload, key: bytes) -> SignedOffer:
    """Merchant-side helper (used by the merchant simulator and tests).
    Production: use per-merchant Ed25519 keys so the gateway only holds public keys."""
    sig = hmac.new(key, payload.canonical().encode(), "sha256").hexdigest()
    return SignedOffer(payload=payload, signature=sig)


class OfferResolver:
    def __init__(self, client: CatalogClient, merchant_keys: Mapping[str, bytes],
                 merchant_payees: Mapping[str, str]):
        """merchant_payees pins, in GATEWAY config, which PayPal merchant id may receive money for each merchant.
        It is deliberately independent of both the signed offer and PayPal's response: three sources must agree."""
        self.client = client
        self.merchant_keys = merchant_keys
        self.merchant_payees = merchant_payees

    async def resolve(self, offer_id: str, quantity: int, now: datetime) -> ResolvedOffer:
        # 1. Fetch from the trusted source. A network failure is a DENY, never a guess.
        try:
            raw = await self.client.fetch(offer_id)
        except Exception as e:  # noqa: BLE001 - any failure to establish the price must fail closed
            raise OfferError(ReasonCode.DENY_OFFER_UNRESOLVED, f"catalog error: {type(e).__name__}") from e
        if raw is None:
            raise OfferError(ReasonCode.DENY_OFFER_UNRESOLVED, "unknown offer_id")

        # 2. Strict parse. Unknown fields, bad decimals, naive datetimes, non-enum categories all fail here.
        try:
            signed = SignedOffer.model_validate(raw)
        except ValidationError as e:
            raise OfferError(ReasonCode.DENY_OFFER_UNRESOLVED, f"malformed offer ({e.error_count()} errors)") from e
        p = signed.payload

        # 3. The catalog must answer the question we asked (blocks offer-swapping).
        if p.offer_id != offer_id:
            raise OfferError(ReasonCode.DENY_OFFER_UNRESOLVED, "offer_id mismatch")

# 4. Authenticity: Asymmetric Ed25519 verification
        key_bytes = self.merchant_keys.get(p.merchant_id)
        if key_bytes is None:
            raise OfferError(ReasonCode.DENY_OFFER_SIGNATURE, "unknown merchant key")
        
        try:
            # Decode the public key from the .env hex string
            verify_key = VerifyKey(binascii.unhexlify(key_bytes))
            sig_bytes = binascii.unhexlify(signed.signature)
            # Verify the signature matches the exact payload
            verify_key.verify(p.canonical().encode(), sig_bytes)
        except (BadSignatureError, binascii.Error):
            raise OfferError(ReasonCode.DENY_OFFER_SIGNATURE, "bad ed25519 signature")

        # 4b. Destination: the signed offer's payee must equal the payee PINNED in gateway config.
        #     A compromised catalog/merchant key can change a price, but cannot redirect funds.
        pinned = self.merchant_payees.get(p.merchant_id)
        if pinned is None or p.payee_merchant_id != pinned:
            raise OfferError(ReasonCode.DENY_PAYEE_NOT_ALLOWED,
                             f"payee {p.payee_merchant_id!r} is not the pinned payee for {p.merchant_id!r}")

        # 5. Freshness: a stale quote is not a price.
        if p.valid_until <= now:
            raise OfferError(ReasonCode.DENY_OFFER_EXPIRED, f"expired {p.valid_until.isoformat()}")

        # 6. Totals computed by us, in Decimal: item_total + shipping + tax.
        return ResolvedOffer.build(p, quantity)
