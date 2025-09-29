#!/usr/bin/env python3
"""Generates a random X25519 keypair."""
import sys
from .common import read_json_stdin, write_json, b64u
from cryptography.hazmat.primitives.asymmetric import x25519

def generate(d: dict = None) -> dict:
    sk = x25519.X25519PrivateKey.generate()
    pk = sk.public_key()
    return {
        "privkey_b64url": b64u(sk.private_bytes_raw()),
        "pubkey_b64url": b64u(pk.public_bytes_raw())
    }

if __name__ == "__main__":
    write_json(generate())
