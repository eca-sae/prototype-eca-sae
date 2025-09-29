#!/usr/bin/env python3
"""
eat_mti_validate.py — Minimal MTI shape checks for EAT used in ECA PoC.
This does *not* perform semantic appraisal; only structural presence/shape.
"""
from __future__ import annotations
import sys, re
from .common import read_json_stdin, write_json, ct_eq

REQ = ["cti","iss","sub","iat","nbf","exp","jti","nonce_b64url",
       "eca.attester_id","eca.vf_sha256","eca.jp_sha256"]

HEX64 = re.compile(r"^[0-9a-f]{64}$")

def main():
    d = read_json_stdin()
    claims = d.get("claims", {})
    errors = []

    # required fields
    for k in REQ:
        if k not in claims:
            errors.append(f"missing:{k}")

    # simple shape checks
    if "cti" in claims:
        # UUID-like string check is lenient here (free-form in PoC)
        if not isinstance(claims["cti"], str): errors.append("cti:not_string")
    for k in ["iss","sub","jti","nonce_b64url"]:
        if k in claims and not isinstance(claims[k], str):
            errors.append(f"{k}:not_string")
    for k in ["iat","nbf","exp"]:
        if k in claims and not isinstance(claims[k], int):
            errors.append(f"{k}:not_int")

    # hex shapes
    if "eca.attester_id" in claims and not HEX64.fullmatch(str(claims["eca.attester_id"])):
        errors.append("eca.attester_id:not_sha256_hex")
    for k in ["eca.vf_sha256","eca.jp_sha256"]:
        if k in claims and not HEX64.fullmatch(str(claims[k])):
            errors.append(f"{k}:not_sha256_hex")

    ok = len(errors) == 0
    write_json({"ok": ok, "errors": errors})
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
