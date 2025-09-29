#!/usr/bin/env python3
"""Derives the Phase 1 authentication key (K_AUTH)."""
from .common import read_json_stdin, write_json, b64d, b64u
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def derive(d: dict) -> dict:
    bf = b64d(d["bf_b64url"])
    session_secret = b64d(d["session_secret_b64url"]) # Using IF as session secret
    eca_uuid = d["eca_uuid"].encode('utf-8')

    ikm = bf + session_secret
    salt = b"ECA:salt:auth:v1" + eca_uuid
    info = b"ECA:info:auth:v1"

    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info)
    key = hkdf.derive(ikm)
    return {"auth_key_b64url": b64u(key)}

if __name__ == "__main__":
    write_json(derive(read_json_stdin()))
