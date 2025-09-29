#!/usr/bin/env python3
"""Generates the HMAC tag for an error status."""
import sys
import uuid
import hmac
import hashlib
from .common import read_json_stdin, write_json, b64d

def generate(d: dict) -> dict:
    bf = b64d(d["bf_b64url"])
    eca = uuid.UUID(str(d["eca_uuid"])).bytes
    code = str(d["error_code"]).encode("ascii")
    key = bf + eca
    tag = hmac.new(key, code, hashlib.sha256).hexdigest()
    return {"hmac_hex": tag}

if __name__ == "__main__":
    try:
        write_json(generate(read_json_stdin()))
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
