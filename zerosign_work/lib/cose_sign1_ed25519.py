#!/usr/bin/env python3
"""Signs a payload as COSE_Sign1 (Ed25519)."""
import sys
from .common import read_json_stdin, write_json, b64d, b64u
from pycose.messages import Sign1Message
from pycose.headers import Algorithm, KID
from pycose.algorithms import EdDSA
from pycose.keys import OKPKey

def sign(d: dict) -> dict:
    payload = b64d(d["payload_b64url"])
    priv = b64d(d["privkey_b64url"])
    kid  = b64d(d.get("kid_b64url",""))

    # Create the COSE key from the PRIVATE key bytes using parameter -4.
    cose_key = OKPKey.from_dict({1: 1, -1: 6, -4: priv}) # kty: OKP, crv: Ed25519, d: privkey

    # Create the message first.
    protected_header = {Algorithm: EdDSA}
    if kid:
        protected_header[KID] = kid
    msg = Sign1Message(phdr=protected_header, uhdr={}, payload=payload)
    # Then assign the key to the message.
    msg.key = cose_key

    return {"cose_sign1_b64url": b64u(msg.encode())}

if __name__ == "__main__":
    try:
        write_json(sign(read_json_stdin()))
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
