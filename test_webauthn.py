import httpx
import asyncio

BASE_URL = "http://127.0.0.1:8000/v1"
ADMIN_TOKEN = "super_secret_admin_123" # Jo humne webauthn_core.py mein dala tha

async def run_test():
    print("🔍 Testing WebAuthn Registration Challenge...")
    async with httpx.AsyncClient() as client:
        # 1. Test Registration Options
        headers = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
        resp = await client.post(f"{BASE_URL}/webauthn/register/options", 
                                 json={"label": "Kislay's Windows PC"},
                                 headers=headers)
        
        if resp.status_code == 200:
            data = resp.json()
            print("\n✅ SUCCESS! Backend generated the WebAuthn Challenge:")
            print(f"👉 RP ID: {data['rp']['id']}")
            print(f"👉 Challenge (Base64Url): {data['challenge']}")
            print(f"👉 User Label: {data['user']['displayName']}")
        else:
            print(f"❌ Failed: {resp.status_code} - {resp.text}")

if __name__ == "__main__":
    asyncio.run(run_test())