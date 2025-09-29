#!/usr/bin/env python3
"""Verifies a COSE_Sign1 (Ed25519) signature."""
import sys
import hmac  # <-- Add this line
from .common import read_json_stdin, write_json, b64d, b64u
from pycose.messages import Sign1Message
from pycose.keys import OKPKey
from pycose.headers import KID

def verify(d: dict) -> dict:
    cose_b = b64d(d["cose_sign1_b64url"])
    pub_b64 = d.get("pubkey_b64url")

    msg = Sign1Message.decode(cose_b)

    # NEW
    if not pub_b64:
        raise ValueError("An explicit pubkey_b64url is required for verification")

    pub_b = b64d(pub_b64)
    msg.key = OKPKey.from_dict({1: 1, -1: 6, -2: pub_b})

    # Security check: verify the KID in the protected header matches the provided key
    kid_from_header = msg.phdr.get(KID)
    if not kid_from_header:
        raise ValueError("Missing KID in protected header")
    if not hmac.compare_digest(kid_from_header, pub_b):
        raise ValueError("KID in header does not match provided public key")

    is_valid = msg.verify_signature()

    payload_b64 = b64u(msg.payload or b"")
    kid_b64 = b64u(kid_from_header) # Use the already fetched KID
    return {"valid": is_valid, "payload_b64url": payload_b64, "protected_headers": {"kid_b64url": kid_b64}}

if __name__ == "__main__":
    try:
        write_json(verify(read_json_stdin()))
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
