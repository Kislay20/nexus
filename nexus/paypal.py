"""Thin PayPal REST client for the enforcement path (AUTHORIZE -> CAPTURE / VOID).

Why raw REST here instead of the Agent Toolkit: you need full control of idempotency
(PayPal-Request-Id), error classification, and exact amounts on the money path.

Error model (important for not losing or duplicating money):
  PayPalDefiniteError -> PayPal answered 4xx. Nothing happened. Safe to release budget.
  PayPalUncertain     -> network/5xx after retries. The call MAY have succeeded. Keep budget held
                         (state UNCERTAIN) and reconcile via webhook / GET. Retries reuse the SAME
                         PayPal-Request-Id so PayPal can de-duplicate them.
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

import httpx

from .models import ResolvedOffer

SANDBOX = "https://api-m.sandbox.paypal.com"


class PayPalDefiniteError(Exception):
    def __init__(self, status: int, body: str):
        super().__init__(f"PayPal {status}: {body[:300]}")
        self.status = status
        self.body = body


class PayPalUncertain(Exception):
    pass


@dataclass(frozen=True)
class AuthFacts:
    """What PayPal says it authorized. We compare this to what WE computed before trusting it."""
    authorization_id: str
    status: str
    amount: Decimal
    currency: str
    payee_merchant_id: str | None
    custom_id: str | None


def parse_authorization(order: dict[str, Any]) -> AuthFacts | None:
    pu = (order.get("purchase_units") or [{}])[0]
    auths = (pu.get("payments") or {}).get("authorizations") or []
    if not auths:
        return None
    a = auths[0]
    return AuthFacts(
        authorization_id=a["id"], status=a.get("status", ""),
        amount=Decimal(a["amount"]["value"]), currency=a["amount"]["currency_code"],
        payee_merchant_id=(pu.get("payee") or {}).get("merchant_id"),
        custom_id=pu.get("custom_id") or a.get("custom_id"))


def build_order_body(resolved: ResolvedOffer, vault_id: str, reservation_id: str, trace_anchor: str = "") -> dict[str, Any]:
    """The order is built ONLY from gateway-resolved facts. No agent-supplied text is in here."""
    o = resolved.offer
    cur = o.currency

    def money(v: Decimal) -> dict[str, str]:
        return {"currency_code": cur, "value": f"{v:.2f}"}

    # Claude's external anchor: Append short hash to custom_id
    cid = f"{reservation_id}:{trace_anchor}" if trace_anchor else reservation_id

    return {
        "intent": "AUTHORIZE",
        "purchase_units": [{
            "reference_id": reservation_id,
            "custom_id": cid[:127],   # Max limit for PayPal custom_id is 127 chars
            "invoice_id": reservation_id,
            "description": o.title[:127],
            "amount": {
                "currency_code": cur, "value": f"{resolved.total:.2f}",
                "breakdown": {"item_total": money(resolved.item_total), "shipping": money(resolved.shipping),
                              "tax_total": money(resolved.tax)},
            },
            "items": [{"name": o.title[:127], "sku": o.sku, "quantity": str(resolved.quantity),
                       "unit_amount": money(o.unit_price), "category": "PHYSICAL_GOODS"}],
        }],
        "payment_source": {"paypal": {"vault_id": vault_id}},
    }


class PayPalClient:
    def __init__(self, client_id: str, secret: str, *, base_url: str = SANDBOX,
                 transport: httpx.AsyncBaseTransport | None = None, max_attempts: int = 3):
        self._id, self._secret, self.max_attempts = client_id, secret, max_attempts
        self._http = httpx.AsyncClient(base_url=base_url, transport=transport, timeout=httpx.Timeout(10.0))
        self._tok: str | None = None
        self._exp = 0.0

    async def _access_token(self) -> str:
        if self._tok and time.monotonic() < self._exp:
            return self._tok
        r = await self._http.post("/v1/oauth2/token", data={"grant_type": "client_credentials"},
                                  auth=(self._id, self._secret))
        r.raise_for_status()
        j = r.json()
        self._tok, self._exp = j["access_token"], time.monotonic() + int(j.get("expires_in", 300)) - 60
        return self._tok

    async def _post(self, path: str, body: dict[str, Any] | None, request_id: str) -> dict[str, Any]:
        last: Exception | None = None
        try:
            tok = await self._access_token()
        except (httpx.TransportError, httpx.HTTPStatusError) as e:
            # Nothing has been sent to a money endpoint yet, so this is safe to treat as a clean failure.
            raise PayPalDefiniteError(0, f"could not obtain access token: {e!r}") from e
        for attempt in range(self.max_attempts):
            try:
                r = await self._http.post(path, json=body, headers={
                    "Authorization": f"Bearer {tok}", "Content-Type": "application/json",
                    "PayPal-Request-Id": request_id,          # same id on every retry => de-duplicated
                    "Prefer": "return=representation"})
            except httpx.TransportError as e:
                last = e
            else:
                if r.status_code >= 500:
                    last = PayPalDefiniteError(r.status_code, r.text)
                elif r.status_code >= 400:
                    raise PayPalDefiniteError(r.status_code, r.text)
                else:
                    return r.json() if r.content else {}
            await asyncio.sleep(0.2 * 2 ** attempt)
        raise PayPalUncertain(f"no definitive answer after {self.max_attempts} attempts: {last!r}")

    # request ids are deterministic per reservation+step so a crash/retry never double-charges
    async def create_authorize_order(self, *, resolved: ResolvedOffer, vault_id: str, reservation_id: str, trace_anchor: str = "") -> dict[str, Any]:
        return await self._post("/v2/checkout/orders", build_order_body(resolved, vault_id, reservation_id, trace_anchor),
                                f"{reservation_id}:create")

    async def authorize_order(self, order_id: str, *, reservation_id: str) -> dict[str, Any]:
        return await self._post(f"/v2/checkout/orders/{order_id}/authorize", None, f"{reservation_id}:authorize")

    async def capture_authorization(self, authorization_id: str, *, amount: Decimal, currency: str,
                                    reservation_id: str) -> dict[str, Any]:
        body = {"amount": {"currency_code": currency, "value": f"{amount:.2f}"}, "final_capture": True}
        return await self._post(f"/v2/payments/authorizations/{authorization_id}/capture", body,
                                f"{reservation_id}:capture")

    async def void_authorization(self, authorization_id: str, *, reservation_id: str) -> dict[str, Any]:
        return await self._post(f"/v2/payments/authorizations/{authorization_id}/void", None,
                                f"{reservation_id}:void")

    async def verify_webhook(self, headers: dict[str, str], raw_body: bytes, body: dict[str, Any], webhook_id: str) -> bool:
        """Strict verification: ONLY accepts the webhook_id pinned in config."""
        import base64
        import zlib
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding

        strict_id = webhook_id.strip().strip('"').strip("'")
        try:
            # 1. Cryptographic X.509 verification
            cert_url = headers.get("paypal-cert-url", "")
            transmission_id = headers.get("paypal-transmission-id", "")
            transmission_time = headers.get("paypal-transmission-time", "")
            transmission_sig = headers.get("paypal-transmission-sig", "")

            if cert_url.startswith("https://api.sandbox.paypal.com/") or cert_url.startswith("https://api.paypal.com/"):
                cert_res = await self._http.get(cert_url)
                if cert_res.status_code == 200:
                    cert = x509.load_pem_x509_certificate(cert_res.content)
                    crc = zlib.crc32(raw_body) & 0xFFFFFFFF
                    sig_bytes = base64.b64decode(transmission_sig)
                    expected_msg = f"{transmission_id}|{transmission_time}|{strict_id}|{crc}".encode("utf-8")
                    try:
                        cert.public_key().verify(sig_bytes, expected_msg, padding.PKCS1v15(), hashes.SHA256())
                        print(f"[Webhook Debug] ✅ Strict X.509 Verified (ID: {strict_id})")
                        return True
                    except Exception:
                        pass # Fall through to REST API if X.509 fails

            # 2. Fallback to PayPal REST API
            tok = await self._access_token()
            payload = {
                "auth_algo": headers.get("paypal-auth-algo"),
                "cert_url": cert_url,
                "transmission_id": transmission_id,
                "transmission_sig": transmission_sig,
                "transmission_time": transmission_time,
                "webhook_id": strict_id,
                "webhook_event": body,
            }
            r = await self._http.post(
                "/v1/notifications/verify-webhook-signature",
                json=payload,
                headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
            )
            if r.status_code == 200 and r.json().get("verification_status") == "SUCCESS":
                print(f"[Webhook Debug] ✅ Strict REST API Verified (ID: {strict_id})")
                return True

            print(f"❌ [Webhook Debug] Verification failed for strict ID: {strict_id}")
            return False
        except Exception as e:
            print(f"[Webhook Debug] Exception: {e}")
            return False
