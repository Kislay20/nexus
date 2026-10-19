import uvicorn
from fastapi import FastAPI
import json
from datetime import datetime, timedelta, timezone
from decimal import Decimal

from nexus.ledger import Ledger
from nexus.models import Warrant, Category, OfferPayload
import binascii
from nacl.signing import SigningKey
from nexus.models import SignedOffer

PRIVATE_KEY_HEX = "2f2cd60ee132ec8a63e74ff624b9bdb7ad6a20f5483dfe86abc37f374c261d31"
signing_key = SigningKey(binascii.unhexlify(PRIVATE_KEY_HEX))

NOW = datetime.now(timezone.utc)
MERCHANT_SECRET = b"change-me" # Matches .env

print("--- INITIALIZING NEXUS SECURE LEDGER ---")
ledger = Ledger("nexus_secure.db")

# 1. Create a $100 Budget Warrant (Approvals required > $50)
warrant = Warrant(
    warrant_id="wrt_demo_001",
    budget_total=Decimal("100.00"),
    max_per_txn=Decimal("100.00"),
    approval_threshold=Decimal("50.00"), 
    allowed_categories=frozenset({Category.ELECTRONICS}),
    allowed_merchants=frozenset({"shopA"}),
    max_txn_per_hour=10,
    not_before=NOW - timedelta(days=1),
    expires_at=NOW + timedelta(days=30),
    vault_id="2al55686jn648980x" # Test PayPal Vault Token
)
try:
    ledger.put_warrant(warrant)
except Exception:
    pass # Already exists

# 2. Generate Agent Bearer Token
token = ledger.issue_agent_token(warrant.warrant_id)
print("\n" + "="*60)
print(f"🚨 COPY THIS AGENT TOKEN TO YOUR agent.py: \n{token}")
print("="*60 + "\n")

# 3. Create the Signed Offers using Ed25519
def make_signed_offer(offer_id, title, price):
    payload = OfferPayload(
        offer_id=offer_id, merchant_id="shopA", payee_merchant_id="CSWSXHLUVXFGY",
        sku=f"SKU-{offer_id}", title=title, category=Category.ELECTRONICS,
        unit_price=Decimal(price), currency="USD", shipping=Decimal("0.00"),
        tax_rate=Decimal("0.00"), valid_until=NOW + timedelta(days=30)
    )
    
    # Sign payload deterministically 
    message = payload.canonical().encode()
    sig_bytes = signing_key.sign(message).signature
    sig_hex = binascii.hexlify(sig_bytes).decode('utf-8')
    
    signed_offer = SignedOffer(payload=payload, signature=sig_hex)
    return json.loads(signed_offer.model_dump_json())

DB = {
    "offer_mouse_40": make_signed_offer("offer_mouse_40", "Logitech Mouse", "40.00"), # < 50 (Auto-Approve)
    "offer_headset_90": make_signed_offer("offer_headset_90", "Gaming Headset", "90.00"), # > 50 (Escalate Hold)
    "offer_monitor_200": make_signed_offer("offer_monitor_200", "Premium Monitor", "200.00") # > 100 (Blocked)
}

app = FastAPI(title="Mock Merchant Catalog")

@app.get("/offers/{offer_id}")
def get_offer(offer_id: str):
    return DB.get(offer_id)

if __name__ == "__main__":
    uvicorn.run(app, port=9000)