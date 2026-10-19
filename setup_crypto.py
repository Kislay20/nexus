from nacl.signing import SigningKey
import binascii

# Generate a new random signing key (Private Key)
signing_key = SigningKey.generate()
private_key_hex = binascii.hexlify(signing_key.encode()).decode('utf-8')

# Obtain the verify key (Public Key) for the gateway
verify_key = signing_key.verify_key
public_key_hex = binascii.hexlify(verify_key.encode()).decode('utf-8')

print("\n--- NEW ED25519 KEYS GENERATED ---")
print(f"PRIVATE KEY (For demo_catalog.py): \n{private_key_hex}\n")
print(f"PUBLIC KEY (For Gateway .env): \n{public_key_hex}\n")