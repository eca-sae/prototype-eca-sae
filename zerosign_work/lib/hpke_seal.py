#!/usr/bin/env python3
import sys
from pyhpke import AEADId, KDFId, KEMId, CipherSuite, KEMKey  # UPDATED: Add KEMKey
from .common import read_json_stdin, write_json, b64d, b64u

def seal(d: dict) -> dict:
    """Callable function for HPKE sealing."""
    pkR_bytes = b64d(d["recipient_pubkey_b64url"])
    pkR_jwk = {
        "kty": "OKP",
        "crv": "X25519",
        "x": b64u(pkR_bytes)
    }
    pkR = KEMKey.from_jwk(pkR_jwk)  # UPDATED: Wrap as KEMKey
    pt = b64d(d["plaintext_b64url"])
    try:
        suite = CipherSuite.new(
            KEMId.DHKEM_X25519_HKDF_SHA256,
            KDFId.HKDF_SHA256,
            AEADId.CHACHA20_POLY1305
        )
        enc, sender = suite.create_sender_context(pkR)
        aad = b64d(d.get("aad_b64url", "")) if "aad_b64url" in d else b""
        ct = sender.seal(pt, aad=aad)  # Pass actual AAD
        out = enc + ct
    except Exception as e:
        raise RuntimeError(f"hpke seal failed: {e}")
    return {"ciphertext_b64url": b64u(out)}

if __name__ == "__main__":
    write_json(seal(read_json_stdin()))
