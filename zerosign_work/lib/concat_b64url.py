#!/usr/bin/env python3
"""Concatenates an array of base64url strings into one base64url string."""
import sys
from .common import read_json_stdin, write_json, b64d, b64u

def concat(d: dict) -> dict:
    arr = d.get("b64url_list", [])
    if not isinstance(arr, list) or not arr:
        raise ValueError("b64url_list must be a non-empty array")
    raw = b"".join(b64d(s) for s in arr)
    return {"b64url_concat": b64u(raw)}

if __name__ == "__main__":
    try:
        write_json(concat(read_json_stdin()))
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
