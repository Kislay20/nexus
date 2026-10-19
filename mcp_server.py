from mcp.server.fastmcp import FastMCP
import requests
import uuid

# 🚨 YAHAN APNA LATEST AGENT TOKEN PASTE KARNA
AGENT_TOKEN = "TERA_ACTUAL_AGENT_TOKEN_YAHAN_AAYEGA"
GATEWAY_URL = "http://127.0.0.1:8000/v1/proposals"

# Create the MCP Server instance
mcp = FastMCP("NexusSecureGateway")

@mcp.tool()
def execute_secure_purchase(offer_id: str, quantity: int = 1, rationale: str = "User requested purchase") -> str:
    """
    Executes a secure purchase through the Nexus Zero-Trust Gateway.
    You MUST provide the exact offer_id from the merchant catalog.
    Returns the cryptographic ledger verification status and transaction outcome.
    """
    print(f"\n[MCP] 🛡️ Intercepting AI Intent: Purchasing {quantity}x {offer_id}")
    
    # Generate fresh idempotency key for this attempt
    idempotency_key = f"mcp_{uuid.uuid4().hex[:16]}"
    headers = {"Authorization": f"Bearer {AGENT_TOKEN}"}
    payload = {
        "offer_id": offer_id,
        "quantity": quantity,
        "idempotency_key": idempotency_key,
        "rationale": rationale
    }
    
    try:
        response = requests.post(GATEWAY_URL, headers=headers, json=payload, timeout=10)
        
        # If the gateway blocks it (401, 403, 422, etc.), catch the error nicely
        if not response.ok:
            return f"❌ GATEWAY BLOCKED TRANSACTION: {response.text}"
            
        data = response.json()
        return f"✅ SUCCESS: {data.get('status')} | Code: {data.get('code')} | Message: {data.get('message')}"
        
    except requests.exceptions.RequestException as e:
        return f"🚨 SYSTEM ERROR: Could not reach Nexus Gateway. Details: {str(e)}"

if __name__ == "__main__":
    print("🚀 Nexus MCP Server Initialized. Ready to connect to any AI Client.")
    # Run using Standard IO (Stdio) which is the default for MCP communication
    mcp.run(transport='stdio')