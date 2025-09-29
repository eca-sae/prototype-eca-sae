#!/usr/bin/env python3
"""Verifies an Ed25519 signature."""
import sys
from .common import read_json_stdin, write_json, b64d
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

def verify(d: dict) -> dict:
    pk = ed25519.Ed25519PublicKey.from_public_bytes(b64d(d["pubkey_b64url"]))
    msg = b64d(d["msg_b64url"])
    sig = b64d(d["sig_b64url"])
    try:
        pk.verify(sig, msg)
        return {"valid": True}
    except InvalidSignature:
        return {"valid": False}

if __name__ == "__main__":
    try:
        write_json(verify(read_json_stdin()))
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
