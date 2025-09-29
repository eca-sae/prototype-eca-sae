#!/usr/bin/env python3
"""Signs a message using an Ed25519 private key."""
import sys
from .common import read_json_stdin, write_json, b64d, b64u
from cryptography.hazmat.primitives.asymmetric import ed25519

def sign(d: dict) -> dict:
    """Signs a payload and returns the raw signature."""
    payload = b64d(d["payload_b64url"])
    priv_key_bytes = b64d(d["privkey_b64url"])

    sk = ed25519.Ed25519PrivateKey.from_private_bytes(priv_key_bytes)
    signature = sk.sign(payload)

    return {"sig_b64url": b64u(signature)}

if __name__ == "__main__":
    try:
        write_json(sign(read_json_stdin()))
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
