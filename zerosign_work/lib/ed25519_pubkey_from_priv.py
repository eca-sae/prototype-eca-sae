#!/usr/bin/env python3
"""Derives an Ed25519 public key from a given private key."""
import sys
from .common import read_json_stdin, write_json, b64d, b64u
from cryptography.hazmat.primitives.asymmetric import ed25519

def derive(d: dict) -> dict:
    priv_raw = b64d(d["privkey_b64url"])
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(priv_raw)
    pk = sk.public_key()
    return {"pubkey_b64url": b64u(pk.public_bytes_raw())}

if __name__ == "__main__":
    try:
        write_json(derive(read_json_stdin()))
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
