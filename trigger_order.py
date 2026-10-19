import httpx
import asyncio
import uuid

TOKEN = input("🔑 Paste your AGENT_TOKEN here: ").strip()

async def place_order():
    req_id = uuid.uuid4().hex[:8]
    print(f"🛒 Sending New Agent Proposal [#{req_id}] for $90 Headset...")
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            "http://127.0.0.1:8000/v1/proposals",
            json={
                "offer_id": "offer_headset_90",
                "quantity": 1,
                "idempotency_key": f"req_{req_id}",
                "rationale": f"Biometric approval test #{req_id}"
            },
            headers={"Authorization": f"Bearer {TOKEN}"}
        )
        
        print(f"Status Code: {resp.status_code}")
        try:
            print("Gateway Response:", resp.json())
        except Exception:
            print("Raw Response Text:", resp.text)

if __name__ == "__main__":
    asyncio.run(place_order())