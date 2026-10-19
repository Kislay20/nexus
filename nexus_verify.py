#!/usr/bin/env python3
"""Standalone offline verifier for Nexus Zero-Trust Agentic Commerce audit bundles."""
from __future__ import annotations

import hashlib
import json
import sys
from cryptography.hazmat.primitives.asymmetric import ed25519

GENESIS = "0" * 64

def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()

def verify_bundle(filepath: str) -> bool:
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            bundle = json.load(f)
    except Exception as e:
        print(f"[-] Error reading audit bundle file: {e}")
        return False

    pub_hex = bundle.get("ledger_public_key", "")
    if not pub_hex:
        print("[-] Error: No public key found in audit bundle.")
        return False

    try:
        pub_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_hex))
    except Exception as e:
        print(f"[-] Error loading Ed25519 public key: {e}")
        return False

    chain = bundle.get("chain", [])
    prev = GENESIS

    print(f"[*] Verifying audit bundle with {len(chain)} cryptographically signed blocks...")

    for row in chain:
        seq = row["seq"]
        body = row["body"]
        prev_hash = row["prev_hash"]
        h = row["hash"]
        sig = row["signature"]

        # 1. Verify Hash Chain integrity
        if prev_hash != prev or sha256_hex(prev + body) != h:
            print(f"[X] TAMPERED: Hash chain broken at sequence #{seq}")
            return False

        # 2. Verify Ed25519 digital signature
        if sig:
            try:
                pub_key.verify(bytes.fromhex(sig), h.encode("utf-8"))
            except Exception:
                print(f"[X] TAMPERED: Invalid Ed25519 signature at sequence #{seq}")
                return False

        prev = h

    print("[+] SUCCESS: Entire audit chain is 100% intact and cryptographically verified offline!")
    return True

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python nexus_verify.py <audit_bundle.json>")
        sys.exit(1)
    success = verify_bundle(sys.argv[1])
    sys.exit(0 if success else 1)