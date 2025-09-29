#!/usr/bin/env python3
"""Computes the SHA256 hex digest of a base64url message."""
import sys
import hashlib
from .common import read_json_stdin, write_json, b64d

def hash_b64url(d: dict) -> dict:
    msg_b64url = d["msg_b64url"]
    h = hashlib.sha256(b64d(msg_b64url)).hexdigest()
    return {"digest_hex": h}

if __name__ == "__main__":
    try:
        write_json(hash_b64url(read_json_stdin()))
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
