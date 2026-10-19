from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Callable

import httpx
import pytest

from nexus.catalog import OfferResolver, sign_offer
from nexus.gateway import Gateway
from nexus.ledger import Ledger
from nexus.models import Category, OfferPayload, Warrant
from nexus.paypal import PayPalClient

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)
MERCHANT_KEY = b"merchant-secret"
PAYEE = "NEXUSMERCHANT01"


def make_offer(offer_id: str = "offer_mouse_60", *, price: str = "60.00", category: Category = Category.ELECTRONICS,
               merchant: str = "shopA", shipping: str = "0.00", tax_rate: str = "0", valid_minutes: int = 30) -> OfferPayload:
    return OfferPayload(offer_id=offer_id, merchant_id=merchant, payee_merchant_id=PAYEE, sku="SKU-" + offer_id[-6:],
                        title=f"Item {offer_id}", category=category, unit_price=Decimal(price), currency="USD",
                        shipping=Decimal(shipping), tax_rate=Decimal(tax_rate), valid_until=NOW + timedelta(minutes=valid_minutes))


def make_warrant(**over: Any) -> Warrant:
    base: dict[str, Any] = dict(
        warrant_id="wrt_demo_001", budget_total=Decimal("100.00"), max_per_txn=Decimal("100.00"),
        approval_threshold=Decimal("75.00"), allowed_categories=frozenset({Category.ELECTRONICS, Category.BOOKS}),
        allowed_merchants=frozenset({"shopA"}), max_txn_per_hour=10, not_before=NOW - timedelta(days=1),
        expires_at=NOW + timedelta(days=2), vault_id="VAULT-TOKEN-1")
    base.update(over)
    return Warrant(**base)


class FakeCatalog:
    """Stands in for the merchant service. `offers` maps offer_id -> raw JSON the merchant would return."""
    def __init__(self) -> None:
        self.offers: dict[str, dict[str, Any]] = {}

    def add(self, payload: OfferPayload, key: bytes = MERCHANT_KEY) -> None:
        self.offers[payload.offer_id] = json.loads(sign_offer(payload, key).model_dump_json())

    async def fetch(self, offer_id: str) -> dict[str, Any] | None:
        return self.offers.get(offer_id)


class FakePayPal:
    """Records every request and answers like PayPal would. `authorized_value` lets a test simulate a lying/buggy response."""
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, Any]] = []
        self.authorized_value: str | None = None
        self.captured_value: str | None = None
        self.payee: str = PAYEE
        self.fail_capture_status: int | None = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        body = json.loads(request.content) if request.content and request.headers.get("content-type", "").startswith("application/json") else None
        self.calls.append((request.method, path, body))
        if path == "/v1/oauth2/token":
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 3000})
        if path == "/v2/checkout/orders":
            pu = body["purchase_units"][0]
            value = self.authorized_value or pu["amount"]["value"]
            return httpx.Response(201, json={"id": "ORDER-1", "status": "COMPLETED", "purchase_units": [{
                "custom_id": pu["custom_id"], "payee": {"merchant_id": self.payee},
                "payments": {"authorizations": [{"id": "AUTH-1", "status": "CREATED",
                                                 "amount": {"currency_code": "USD", "value": value}}]}}]})
        if path.endswith("/capture"):
            if self.fail_capture_status:
                return httpx.Response(self.fail_capture_status, json={"name": "AUTHORIZATION_VOIDED"})
            return httpx.Response(201, json={"id": "CAP-1", "status": "COMPLETED", "amount": {
                "currency_code": "USD", "value": self.captured_value or body["amount"]["value"]}})
        if path.endswith("/void"):
            return httpx.Response(204)
        return httpx.Response(404, json={"name": "NOT_FOUND"})

    def paths(self) -> list[str]:
        return [p for _, p, _ in self.calls if p != "/v1/oauth2/token"]


@pytest.fixture
def env(tmp_path):
    ledger = Ledger(str(tmp_path / "nexus.db"))
    warrant = make_warrant()
    ledger.put_warrant(warrant)
    catalog = FakeCatalog()
    pp = FakePayPal()
    paypal = PayPalClient("id", "secret", transport=httpx.MockTransport(pp.handler), max_attempts=1)
    gw = Gateway(ledger, OfferResolver(catalog, {"shopA": MERCHANT_KEY}), paypal, clock=lambda: NOW, strict_payee=True)
    return type("Env", (), dict(ledger=ledger, warrant=warrant, catalog=catalog, pp=pp, gw=gw))
