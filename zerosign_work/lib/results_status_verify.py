#!/usr/bin/env python3
from __future__ import annotations
import sys, json, uuid, hmac, hashlib
from .common import read_json_stdin, write_json, b64d

def main():
    d = read_json_stdin()
    try:
        bf = b64d(d["bf_b64url"])
        eca = d["eca_uuid"].lower()
        code = d["error_code"].encode("ascii")
        tag_hex = str(d["hmac_hex"]).lower()
    except KeyError as e:
        print(f"error: missing field {e}", file=sys.stderr); sys.exit(2)

    u = uuid.UUID(eca)
    key = bf + u.bytes
    expected = hmac.new(key, code, hashlib.sha256).hexdigest().lower()
    write_json({"valid": hmac.compare_digest(expected, tag_hex)})

if __name__ == "__main__":
    main()
