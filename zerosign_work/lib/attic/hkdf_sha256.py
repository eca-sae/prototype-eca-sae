#!/usr/bin/env python3
from __future__ import annotations
import sys
from common import read_json_stdin, write_json, b64d, b64u
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def main():
    d = read_json_stdin()
    try:
        ikm = b64d(d["ikm_b64url"])
        salt = b64d(d.get("salt_b64url","")) if "salt_b64url" in d else None
        info = d.get("info_utf8","").encode("utf-8")
        length = int(d.get("length", 32))
    except KeyError as e:
        print(f"error: missing field {e}", file=sys.stderr); sys.exit(2)
    hk = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    okm = hk.derive(ikm)
    write_json({"okm_b64url": b64u(okm)})

if __name__ == "__main__":
    main()
