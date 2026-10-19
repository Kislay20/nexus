import os
import httpx
from dotenv import load_dotenv

load_dotenv(override=True)

def get_telegram_config():
    load_dotenv(override=True)
    bot_token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")
    frontend_url = os.getenv("WEBAUTHN_ORIGIN", "").split(",")[0].strip().rstrip("/")
    return bot_token, chat_id, frontend_url

async def send_telegram_alert(message: str, reservation_id: str | None = None):
    bot_token, chat_id, frontend_url = get_telegram_config()
    if not bot_token or not chat_id:
        print("⚠️ Telegram Token ya Chat ID missing hai!")
        return

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload: dict = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "HTML",
        "link_preview_options": {"is_disabled": True},
    }

    if reservation_id and frontend_url.startswith("https://"):
        payload["reply_markup"] = {
            "inline_keyboard": [
                [
                    {
                        "text": "🛡️ Approve (Biometrics)",
                        "url": f"{frontend_url}/?action=approve&id={reservation_id}",
                    },
                    {
                        "text": "❌ Reject Order",
                        "url": f"{frontend_url}/?action=reject&id={reservation_id}",
                    },
                ]
            ]
        }

    async with httpx.AsyncClient() as client:
        try:
            await client.post(url, json=payload, timeout=5.0)
        except Exception as e:
            print(f"Telegram Alert Error: {e}")