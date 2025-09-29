#!/usr/bin/env python3
"""Encodes a dictionary of claims into a CBOR EAT."""
import sys
import cbor2
from .common import read_json_stdin, write_json, b64u

def encode(d: dict) -> dict:
    claims = d.get("claims", {})
    if not isinstance(claims, dict):
        raise ValueError("claims must be a dictionary")
    b = cbor2.dumps(claims)
    return {"eat_cbor_b64url": b64u(b)}

if __name__ == "__main__":
    try:
        write_json(encode(read_json_stdin()))
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
