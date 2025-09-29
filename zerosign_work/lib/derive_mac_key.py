#!/usr/bin/env python3
"""Derives the final Proof-of-Possession HMAC key (K_MAC) from BF and VF."""
from .common import read_json_stdin, write_json, b64d, b64u
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def derive(d: dict) -> dict:
    bf = b64d(d["bf_b64url"])
    vf = b64d(d["vf_b64url"])
    eca_uuid = d["eca_uuid"].encode('utf-8')

    ikm = bf + vf
    salt = b"ECA:salt:kmac:v1" + eca_uuid
    info = b"ECA:info:kmac:v1"

    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info)
    key = hkdf.derive(ikm)
    return {"mac_key_b64url": b64u(key)}

if __name__ == "__main__":
    write_json(derive(read_json_stdin()))
