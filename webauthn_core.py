import os
import hashlib
import json
from dotenv import load_dotenv

load_dotenv(override=True)

# --- CONFIGURATION ---
RP_ID = os.environ.get("WEBAUTHN_RP_ID", "localhost")
RP_NAME = os.environ.get("WEBAUTHN_RP_NAME", "Nexus Gateway")
# Handle multiple origins if comma-separated
ORIGINS = [o.strip() for o in os.environ.get("WEBAUTHN_ORIGIN", "http://localhost:3000").split(",")]
APPROVAL_MODE = os.environ.get("APPROVAL_MODE", "click") # 'click' for demo/CI, 'passkey' for real FaceID
ADMIN_BOOTSTRAP_TOKEN = os.environ.get("ADMIN_BOOTSTRAP_TOKEN", "super_secret_admin_123")

# --- CHALLENGE GENERATION ---
def canonical(obj: dict) -> bytes:
    """Strictly determinist JSON serialization for cryptographic hashing."""
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode('utf-8')

def derive_challenge(tx: dict, nonce: bytes) -> tuple[bytes, dict]:
    """
    Binds the WebAuthn challenge directly to the exact transaction facts.
    If the hacker changes even 1 cent after the prompt, the FaceID signature becomes invalid.
    """
    pre = {
        'v': 1,
        'reservation_id': tx['reservation_id'],
        'offer_hash': tx['offer_hash'],
        'amount': str(tx['amount']),          # Force string to avoid float precision issues
        'currency': tx['currency'],
        'payee_id': tx['payee_id'],
        'warrant_id': tx['warrant_id'],
        'offer_expires_at': tx['offer_expires_at'],
        'nonce': nonce.hex(),
    }
    # SHA-256 hash of the canonical transaction details becomes the challenge
    challenge_hash = hashlib.sha256(canonical(pre)).digest()
    return challenge_hash, pre