#!/usr/bin/env python3
import sys
from pyhpke import AEADId, KDFId, KEMId, CipherSuite, KEMKey  # UPDATED: Add KEMKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # For deriving public
from .common import read_json_stdin, write_json, b64d, b64u

def kem_pub_len(kem):
    return 32

def open_sealed(d: dict) -> dict:
    """Callable function for HPKE opening."""
    skR_bytes = b64d(d["recipient_privkey_b64url"])
    skR_crypto = X25519PrivateKey.from_private_bytes(skR_bytes)
    pkR_bytes = skR_crypto.public_key().public_bytes_raw()  # Derive public bytes
    skR_jwk = {
        "kty": "OKP",
        "crv": "X25519",
        "x": b64u(pkR_bytes),
        "d": b64u(skR_bytes)
    }
    skR = KEMKey.from_jwk(skR_jwk)  # UPDATED: Wrap as KEMKey
    blob = b64d(d["ciphertext_b64url"])
    enc_len = kem_pub_len("DHKEM_X25519")
    enc, ct = blob[:enc_len], blob[enc_len:]
    try:
        suite = CipherSuite.new(
            KEMId.DHKEM_X25519_HKDF_SHA256,
            KDFId.HKDF_SHA256,
            AEADId.CHACHA20_POLY1305
        )
        ctx = suite.create_recipient_context(enc, skR)
        aad = b64d(d.get("aad_b64url", "")) if "aad_b64url" in d else b""
        pt = ctx.open(ct, aad=aad)  # Pass actual AAD
    except Exception as e:
        raise RuntimeError(f"hpke open failed: {e}")
    return {"plaintext_b64url": b64u(pt)}

if __name__ == "__main__":
    write_json(open_sealed(read_json_stdin()))
