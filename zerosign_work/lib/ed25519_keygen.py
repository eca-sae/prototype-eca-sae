#!/usr/bin/env python3
"""Generates a random Ed25519 keypair."""
import sys
from cryptography.hazmat.primitives.asymmetric import ed25519

# --- NEW: Robust Import Logic ---
# This allows the script to be run standalone OR imported as a module.
if __name__ == "__main__" and __package__ is None:
    from os import path
    sys.path.append(path.dirname(path.dirname(path.abspath(__file__))))
    from lib.common import write_json, b64u
else:
    from .common import write_json, b64u
# --------------------------------

def generate(d: dict = None) -> dict:
    sk = ed25519.Ed25519PrivateKey.generate()
    pk = sk.public_key()
    return {
        "privkey_b64url": b64u(sk.private_bytes_raw()),
        "pubkey_b64url": b64u(pk.public_bytes_raw())
    }

if __name__ == "__main__":
    write_json(generate())
