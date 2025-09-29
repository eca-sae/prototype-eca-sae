#!/usr/bin/env python3
"""Derives the final composite signing key from BF and VF."""
from .common import read_json_stdin, write_json, b64d, b64u
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def derive(d: dict) -> dict:
    bf = b64d(d["bf_b64url"])
    vf = b64d(d["vf_b64url"])
    eca_uuid = d["eca_uuid"].encode('utf-8')

    ikm = bf + vf
    salt = b"ECA:salt:composite-identity:v1" + eca_uuid
    info = b"ECA:info:composite-identity:v1"

    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info)
    seed = hkdf.derive(ikm)

    sk = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    pk = sk.public_key()

    return {
        "privkey_b64url": b64u(sk.private_bytes_raw()),
        "pubkey_b64url": b64u(pk.public_bytes_raw())
    }

if __name__ == "__main__":
    write_json(derive(read_json_stdin()))
