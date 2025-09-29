#!/usr/bin/env python3
"""Verifies an HMAC-SHA256 tag in constant time."""
import sys
import hmac
from .common import read_json_stdin, write_json, b64d

def verify(d: dict) -> dict:
    key = b64d(d["key_b64url"])
    msg = b64d(d["msg_b64url"])
    tag_to_check = b64d(d["mac_b64url"])
    h = hmac.new(key, msg, 'sha256')
    return {"valid": hmac.compare_digest(h.digest(), tag_to_check)}

if __name__ == "__main__":
    write_json(verify(read_json_stdin()))
