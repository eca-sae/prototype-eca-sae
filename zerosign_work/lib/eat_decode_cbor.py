#!/usr/bin/env python3
"""Decodes a CBOR EAT."""
import sys
import cbor2
from .common import read_json_stdin, write_json, b64d

def decode(d: dict) -> dict:
    eat_b64 = d["eat_cbor_b64url"]
    b = b64d(eat_b64)
    claims = cbor2.loads(b)
    return {"claims": claims}

if __name__ == "__main__":
    try:
        write_json(decode(read_json_stdin()))
    except Exception as e:
        print(f"error: cbor decode failed: {e}", file=sys.stderr)
        sys.exit(1)
