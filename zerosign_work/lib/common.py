#!/usr/bin/env python3
"""
common.py — Shared helpers for ZeroSign ECA/SAE library CLIs.

All CLIs follow the same contract:
- Read a single JSON object from STDIN.
- Write a single JSON object to STDOUT.
- Fail with a non‑zero exit on any error, printing a short message to STDERR.

SAE alignment:
- All binary values are encoded as *unpadded* base64url.
- Helpers here normalize base64url padding and provide constant‑time equality.
"""
from __future__ import annotations
import sys, json, base64, hmac, re

# ---------- Base64url (unpadded) ----------
def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def b64d(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

# ---------- JSON IO ----------
def read_json_stdin() -> dict:
    try:
        return json.load(sys.stdin)
    except Exception as e:
        print(f"error: invalid JSON on stdin: {e}", file=sys.stderr)
        sys.exit(2)

def write_json(obj: dict) -> None:
    json.dump(obj, sys.stdout, separators=(",",":"))
    sys.stdout.write("\n")

# ---------- Validation helpers ----------
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
def is_sha256_hex(s: str) -> bool:
    return bool(_HEX64.fullmatch(s))

def ct_eq(a: str, b: str) -> bool:
    # constant‑time compare for ASCII hex / base64url strings
    return hmac.compare_digest(a, b)

def require_fields(obj: dict, keys: list[str]) -> list[str]:
    missing = [k for k in keys if k not in obj]
    return missing
