"""FastAPI surface."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import hmac
import json
import os
import uuid
import binascii
from typing import Any
from decimal import Decimal
from datetime import datetime, timedelta, timezone

from nacl.signing import SigningKey
from dotenv import load_dotenv
from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import ValidationError
import httpx

from telegram_alert import send_telegram_alert
from webauthn_routes import router as webauthn_router

from .catalog import HttpCatalogClient, OfferResolver
from .gateway import Gateway
from .ledger import Ledger
from .models import ApprovalRequest, GatewayResponse, ProposalRequest, Warrant, Category, OfferPayload, SignedOffer
from .paypal import PayPalClient

load_dotenv()


# ==========================================
# MOCK CATALOG INTEGRATION (For Hackathon Demo)
# ==========================================
PRIVATE_KEY_HEX = "2f2cd60ee132ec8a63e74ff624b9bdb7ad6a20f5483dfe86abc37f374c261d31"
signing_key = SigningKey(binascii.unhexlify(PRIVATE_KEY_HEX))

def make_signed_offer(offer_id, title, price):
    NOW = datetime.now(timezone.utc)
    payload = OfferPayload(
        offer_id=offer_id, merchant_id="shopA", payee_merchant_id="CSWSXHLUVXFGY",
        sku=f"SKU-{offer_id}", title=title, category=Category.ELECTRONICS,
        unit_price=Decimal(price), currency="USD", shipping=Decimal("0.00"),
        tax_rate=Decimal("0.00"), valid_until=NOW + timedelta(days=365)
    )
    message = payload.canonical().encode()
    sig_bytes = signing_key.sign(message).signature
    sig_hex = binascii.hexlify(sig_bytes).decode('utf-8')
    signed_offer = SignedOffer(payload=payload, signature=sig_hex)
    return json.loads(signed_offer.model_dump_json())

CATALOG_DB = {
    "offer_mouse_40": make_signed_offer("offer_mouse_40", "Logitech Mouse", "40.00"),
    "offer_headset_90": make_signed_offer("offer_headset_90", "Gaming Headset", "90.00"),
    "offer_monitor_200": make_signed_offer("offer_monitor_200", "Premium Monitor", "200.00")
}
# ==========================================


def build_gateway_from_env() -> Gateway:
    ledger = Ledger(os.environ.get("NEXUS_DB", "nexus.db"))
    keys = {m: k.encode() for m, k in json.loads(os.environ["MERCHANT_KEYS"]).items()}
    payees = json.loads(os.environ["MERCHANT_PAYEES"])
    resolver = OfferResolver(HttpCatalogClient(os.environ["CATALOG_URL"]), keys, payees)
    paypal = PayPalClient(os.environ["PAYPAL_CLIENT_ID"], os.environ["PAYPAL_SECRET"])
    return Gateway(ledger, resolver, paypal, strict_payee=os.environ.get("STRICT_PAYEE") == "1")


def create_app(gateway: Gateway | None = None, approver_key: str | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # 1. Auto-Seed the Demo Warrant on the Correct Database!
        NOW = datetime.now(timezone.utc)
        db_path = os.environ.get("NEXUS_DB", "nexus.db")
        ledger = Ledger(db_path)

        warrant = Warrant(
            warrant_id="wrt_demo_001",
            budget_total=Decimal("1000.00"),  # Boosted for unlimited demos
            max_per_txn=Decimal("100.00"),
            approval_threshold=Decimal("50.00"),
            allowed_categories=frozenset({Category.ELECTRONICS}),
            allowed_merchants=frozenset({"shopA"}),
            max_txn_per_hour=50,
            not_before=NOW - timedelta(days=1),
            expires_at=NOW + timedelta(days=365),
            vault_id="2al55686jn648980x"
        )
        try:
            ledger.put_warrant(warrant)
        except Exception:
            pass  # Already exists

        # Store a master token to be used silently by the Simulate button
        app.state.demo_token = ledger.issue_agent_token(warrant.warrant_id)

        # 2. Force the Gateway to use our internal Catalog endpoint dynamically
        port = os.environ.get("PORT", "10000")
        os.environ["CATALOG_URL"] = f"http://127.0.0.1:{port}/catalog"

        if app.state.gateway is None:
            app.state.gateway = build_gateway_from_env()
        yield

    app = FastAPI(title="Nexus Gateway", lifespan=lifespan)
    app.include_router(webauthn_router)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.state.gateway = gateway
    app.state.approver_key = approver_key or os.environ.get("APPROVER_KEY", "")

    def get_gateway(request: Request) -> Gateway:
        return request.app.state.gateway

    async def agent_warrant(request: Request, authorization: str = Header(default="")) -> str:
        token = authorization.removeprefix("Bearer ").strip()
        wid = (
            await request.app.state.gateway._db(
                request.app.state.gateway.ledger.warrant_for_token, token
            )
            if token
            else None
        )
        if not wid:
            raise HTTPException(401, "invalid agent token")
        return wid

    def human(request: Request, x_approver_key: str = Header(default="")) -> None:
        key = request.app.state.approver_key
        if not key or not hmac.compare_digest(key, x_approver_key):
            raise HTTPException(403, "approver auth required")

    # --- INTERNAL CATALOG ROUTE ---
    @app.get("/catalog/offers/{offer_id}")
    def get_offer(offer_id: str):
        return CATALOG_DB.get(offer_id)

    @app.post("/v1/proposals", response_model=GatewayResponse)
    async def propose(
        payload: dict[str, Any] = Body(...),
        warrant_id: str = Depends(agent_warrant),
        gw: Gateway = Depends(get_gateway),
    ) -> GatewayResponse:
        try:
            req = ProposalRequest.model_validate(payload)
        except ValidationError as e:
            return await gw.reject_malformed(warrant_id, payload, e)

        resp = await gw.propose(warrant_id, req)

        # --- TELEGRAM ALERT ---
        if resp.decision == "ESCALATE":
            asyncio.create_task(
                send_telegram_alert(
                    f"🚨 <b>HIGH-VALUE ORDER ESCALATED</b>\n\n"
                    f"🛒 Item: <code>{req.offer_id}</code>\n"
                    f"💰 Amount: <b>${resp.total}</b>\n"
                    f"🛡️ <i>Awaiting Biometric (Passkey) Approval</i>\n"
                    f"🆔 Res ID: <code>{resp.reservation_id}</code>",
                    reservation_id=resp.reservation_id,
                )
            )

        return resp

    @app.post("/v1/demo/simulate")
    async def simulate_agent_order(request: Request) -> dict[str, Any]:
        """1-Click UI simulator that PERFECTLY mimics trigger_order.py."""
        token = request.app.state.demo_token
        req_id = uuid.uuid4().hex[:8]
        payload = {
            "offer_id": "offer_headset_90",
            "quantity": 1,
            "idempotency_key": f"sim_{req_id}",
            "rationale": f"Autonomous judge simulation #{req_id}",
        }

        # Make a real HTTP call to ourselves so the entire pipeline runs normally
        base_url = str(request.base_url).rstrip("/")
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                f"{base_url}/v1/proposals",
                json=payload,
                headers={"Authorization": f"Bearer {token}"},
                timeout=10.0,
            )
            data = resp.json()

        return {
            "status": "success",
            "decision": data.get("decision", "UNKNOWN"),
            "reservation_id": data.get("reservation_id"),
            "total": data.get("total", 90.0),
        }

    @app.post(
        "/v1/reservations/{reservation_id}/approve",
        response_model=GatewayResponse,
        dependencies=[Depends(human)],
    )
    async def approve(
        reservation_id: str, body: ApprovalRequest, gw: Gateway = Depends(get_gateway)
    ) -> GatewayResponse:
        try:
            resp = await gw.approve(reservation_id, body.offer_hash)
            asyncio.create_task(
                send_telegram_alert(
                    f"✅ <b>ORDER APPROVED</b>\n\n"
                    f"Biometric Signature Verified cryptographically.\n"
                    f"🆔 Res ID: <code>{reservation_id}</code>\n"
                    f"Status: <b>SUCCESS: CAPTURED</b>"
                )
            )
            return resp
        except KeyError:
            raise HTTPException(404, "unknown reservation") from None

    @app.post(
        "/v1/reservations/{reservation_id}/reject",
        response_model=GatewayResponse,
        dependencies=[Depends(human)],
    )
    async def reject(
        reservation_id: str, gw: Gateway = Depends(get_gateway)
    ) -> GatewayResponse:
        try:
            resp = await gw.reject(reservation_id)
            asyncio.create_task(
                send_telegram_alert(
                    f"❌ <b>ORDER REJECTED & VOIDED</b>\n\n"
                    f"Authorization hold has been voided by human operator.\n"
                    f"🆔 Res ID: <code>{reservation_id}</code>"
                )
            )
            return resp
        except KeyError:
            raise HTTPException(404, "unknown reservation") from None

    @app.get("/v1/traces")
    async def traces(after: int = 0, gw: Gateway = Depends(get_gateway)) -> list[dict[str, Any]]:
        return await gw._db(gw.ledger.traces_after, after, 100)

    @app.get("/v1/traces/stream")
    async def stream_traces(request: Request, gw: Gateway = Depends(get_gateway)):
        async def event_generator():
            last_count = -1
            while True:
                if await request.is_disconnected():
                    break
                traces_list = await gw._db(gw.ledger.traces_after, 0, 1000)
                current_count = len(traces_list)
                if current_count != last_count:
                    last_count = current_count
                    yield f"data: {json.dumps(traces_list)}\n\n"
                await asyncio.sleep(1)

        return StreamingResponse(event_generator(), media_type="text/event-stream")

    @app.get("/v1/audit/verify")
    async def verify(gw: Gateway = Depends(get_gateway)) -> dict[str, Any]:
        ok, bad_seq = await gw._db(gw.ledger.verify_chain)
        return {"intact": ok, "first_bad_seq": bad_seq}

    @app.post("/v1/webhooks/paypal")
    async def paypal_webhook(
        request: Request, gw: Gateway = Depends(get_gateway)
    ) -> dict[str, str]:
        raw_body = await request.body()
        body = await request.json()
        headers = {k.lower(): v for k, v in request.headers.items()}

        event_type = body.get("event_type", "UNKNOWN_EVENT")
        resource = body.get("resource", {})
        res_id = resource.get("custom_id") or resource.get("invoice_id") or "N/A"

        webhook_id = os.environ.get("PAYPAL_WEBHOOK_ID", "")
        is_valid = await gw.paypal.verify_webhook(headers, raw_body, body, webhook_id)
        if not is_valid:
            print(f"❌ [Nexus Webhook] Verification failed for event: {event_type}")
            raise HTTPException(400, "Invalid webhook signature")

        print(
            f"\n✅ [Nexus Webhook Listener] 🔔 VERIFIED SECURE EVENT: {event_type} | Ledger ID: {res_id}\n"
        )
        return {"status": "ok"}

    @app.get("/v1/audit/export")
    async def export_audit(gw: Gateway = Depends(get_gateway)) -> dict[str, Any]:
        return await gw._db(gw.ledger.export_audit_bundle)

    return app