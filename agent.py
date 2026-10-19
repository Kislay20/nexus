import os
import requests
import uuid
from google import genai
from google.genai import types
from dotenv import load_dotenv

# Load variables from .env
load_dotenv()

# 🚨 PASTE YOUR FRESH TOKEN FROM TERMINAL 1 HERE 🚨
AGENT_TOKEN = "gJ7blhNR8e52KLWGV63LAJsdHnGkebOK4NJBRXwinO4"
GATEWAY_URL = "http://127.0.0.1:8000/v1/proposals"

# 1. Define the Tool for the AI (Renamed to match MCP architecture)
def execute_secure_purchase(offer_id: str, quantity: int = 1):
    """
    Executes a secure purchase through the Nexus Zero-Trust Gateway.
    You MUST provide the exact offer_id from the merchant catalog.
    """
    print(f"\n[Nexus Security Protocol] 🛡️ Intercepting AI Intent: Purchasing {quantity}x {offer_id}...")
    
    # A fresh idempotency key is required for every new purchase attempt
    fresh_idempotency_key = f"demo_{uuid.uuid4().hex[:16]}"
    
    try:
        response = requests.post(
            GATEWAY_URL,
            headers={"Authorization": f"Bearer {AGENT_TOKEN}"},
            json={
                "offer_id": offer_id,
                "quantity": quantity,
                "idempotency_key": fresh_idempotency_key,
                "rationale": "User requested this item via AI."
            },
            timeout=10
        )
        # Handle HTTP errors explicitly for cleaner AI feedback
        if not response.ok:
            return {"error": "Gateway Blocked", "status_code": response.status_code, "details": response.text}
            
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": "Network/System Error", "details": str(e)}

# 2. Initialize the Gemini Client
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

# Configure the agent with strict instructions
system_prompt = """
You are Nexus, an autonomous AI shopping assistant. Your job is to help the user buy things. 
When ready to purchase, you MUST use the execute_secure_purchase tool. 
Do not make up IDs. After the tool runs, format the result beautifully for the user, stating if it was CAPTURED, BLOCKED, or ESCALATED.
"""

config = types.GenerateContentConfig(
    system_instruction=system_prompt,
    tools=[execute_secure_purchase],
    temperature=0.0
)

# 3. Start Chat 
chat = client.chats.create(model="gemini-3.8-flash", config=config)

print("="*60)
print("🤖 NEXUS AUTONOMOUS AGENT INITIALIZED")
print("🔒 Zero-Trust Gateway Status: ONLINE")
print("Type 'quit' to exit.")
print("="*60)

while True:
    user_input = input("\nYou: ")
    if user_input.lower() in ['quit', 'exit']:
        print("Shutting down Nexus Agent...")
        break

    print("\nNexus is thinking...")
    try:
        response = chat.send_message(user_input)
        print(f"\nNexus: {response.text}")
    except Exception as e:
        print(f"\n[Connection Error: {str(e)}]\nMake sure your internet is stable and try again.")