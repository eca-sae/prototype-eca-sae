#!/usr/bin/env python3
"""Derives the deterministic encryption keypair from BF and the session secret (IF)."""
from .common import read_json_stdin, write_json, b64d, b64u
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def derive(d: dict) -> dict:
    bf = b64d(d["bf_b64url"])
    session_secret = b64d(d["session_secret_b64url"])
    eca_uuid = d["eca_uuid"].encode('utf-8')

    ikm = bf + session_secret
    salt = b"ECA:salt:encryption:v1" + eca_uuid
    info = b"ECA:info:encryption:v1"

    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info)
    seed = hkdf.derive(ikm)

    sk = x25519.X25519PrivateKey.from_private_bytes(seed)
    pk = sk.public_key()

    return {
        "privkey_b64url": b64u(sk.private_bytes_raw()),
        "pubkey_b64url": b64u(pk.public_bytes_raw())
    }

if __name__ == "__main__":
    write_json(derive(read_json_stdin()))
