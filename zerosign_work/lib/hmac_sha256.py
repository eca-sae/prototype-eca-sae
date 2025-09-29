#!/usr/bin/env python3
"""Computes an HMAC-SHA256 tag."""
import sys
import hmac
import hashlib
from .common import read_json_stdin, write_json, b64d, b64u

def mac(d: dict) -> dict:
    key = b64d(d["key_b64url"])
    msg = b64d(d["msg_b64url"])
    h = hmac.new(key, msg, hashlib.sha256)
    return {"hmac_b64url": b64u(h.digest())}

if __name__ == "__main__":
    write_json(mac(read_json_stdin()))
