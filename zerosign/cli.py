#!/usr/bin/env python3
"""
cli.py - Project ZeroSign - Prototype implementation for ECA/SAE
============================================================================
Copyright 2025 Nathanael Ritz

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

============================================================================

This toolchain implements the three-phase attestation ceremony where an ephemeral
compute instance (Attester) proves its identity to a Verifier without
any pre-shared operational credentials - the "privileged credential vacuum".

Protocol Flow (maps to formal model events):
  Phase 1: Attester proves BF+IF possession → AttesterInitiates
  Phase 2: Verifier releases VF → VFReleased
  Phase 3: Attester proves BF+VF → VerifierAccepts

Security Gates (Section 4.1 of draft):
  Gate 1: MAC Verification (Phase 1 authentication)
  Gate 2: Instance Authorization (policy check)
  Gate 3: IHB Validation (BF+IF binding)
  Gate 4: KEM Public Key Match (prevents substitution)
  Gate 5: Evidence Time Window (freshness)
  Gate 6: EAT Schema Compliance (structure)
  Gate 7: EAT Signature (Phase 3 authentication)
  Gate 8: Nonce Match (freshness proof)
  Gate 9: JP Validation (joint possession)
  Gate 10: PoP Validation (final proof)
  Gate 11: Identity Uniqueness (replay prevention)
"""

import argparse
import os
import sys
import json
import time
import base64
import pathlib
import uuid
import yaml
import random
import hmac
import hashlib
import re
import requests
import struct  # For fixed-size padding (side-channel resistance)
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Import ECA cryptographic library modules
# These implement the primitives defined in Appendix B of draft-ritz-eca-00
from zerosign_work.lib import (
    derive_auth_key,     # Phase 1 MAC key derivation (Section B.3)
    derive_enc_key,      # X25519 ephemeral key (Section B.3)
    deterministic_keys as derive_composite_key,  # Final Ed25519 key (Section B.3)
    derive_mac_key,      # PoP HMAC key (Section B.4.3)
    hpke_seal,          # HPKE encryption for VF (RFC 9180)
    hpke_open,          # HPKE decryption
    hmac_sha256,        # HMAC-SHA256 (RFC 2104)
    verify_mac,         # Constant-time MAC verification
    eat_encode_cbor,    # EAT encoding (RFC 8392)
    eat_decode_cbor,    # EAT decoding
    cose_sign1_ed25519, # COSE_Sign1 (RFC 8152)
    cose_verify1_ed25519,
    concat_b64url,      # Binary concatenation helper
    sha256_hex,         # SHA-256 (RFC 6234)
    sha512_hex,
    ed25519_pubkey_from_priv,
    results_status_hmac  # SAE error signaling (Section 4.4)
)

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Global timer for performance metrics
SCRIPT_START_TIME = 0

def log(role, msg):
    """Structured logging with timing information."""
    elapsed = time.time() - SCRIPT_START_TIME
    print(f"[{role}] {elapsed:.2f}s - {msg}", flush=True)

def log_err(role, msg):
    """Error logging to stderr."""
    elapsed = time.time() - SCRIPT_START_TIME
    print(f"[{role}] {elapsed:.2f}s - {msg}", file=sys.stderr, flush=True)

# === Base64url helpers (RFC 4648, unpadded) ===
def b64url(b: bytes) -> str:
    """Encode bytes as unpadded base64url."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def b64d(s: str) -> bytes:
    """Decode unpadded base64url string."""
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))

# === Configuration helpers ===
def read_yaml(path):
    """Read manifest file (YAML format)."""
    with open(path, "r") as f:
        return yaml.safe_load(f)

def ensure_dir(p):
    """Create directory if it doesn't exist."""
    pathlib.Path(p).mkdir(parents=True, exist_ok=True)

def pad_to_fixed_size(data: bytes, size: int = 2048) -> bytes:
    """
    Fixed-size padding for side-channel resistance (Section 7.3).
    Uses length prefix to enable unambiguous parsing.

    This prevents timing attacks by ensuring all artifacts appear
    to be the same size to network observers.
    """
    len_prefix = struct.pack('>I', len(data))  # 4-byte big-endian length
    padded_data = len_prefix + data
    padding_len = size - len(padded_data)
    if padding_len < 0:
        raise ValueError("Data exceeds fixed size")
    return padded_data + b'\x00' * padding_len

def unpad_fixed_size(padded: bytes) -> bytes:
    """Remove fixed-size padding."""
    data_len = struct.unpack('>I', padded[:4])[0]
    return padded[4:4 + data_len]

def write_bytes_atomic(p_str, b, role="SYS", pad_size=None):
    """
    Atomically write bytes to file (SAE requirement).
    The atomic write ensures the status indicator appears instantly
    and completely (Section 4.2 of SAE draft).
    """
    p = pathlib.Path(p_str)
    ensure_dir(p.parent)
    if pad_size:
        b = pad_to_fixed_size(b, pad_size)
    tmp_p = p.with_suffix(p.suffix + ".tmp")
    tmp_p.write_bytes(b)
    tmp_p.rename(p)  # Atomic on POSIX
    log(role, f"PUBLISHED: {p_str}")

def poll_for_url(url, role, polling_cfg):
    """
    Poll for artifact presence (SAE transport pattern).
    Implements exponential backoff with jitter as required
    by SAE Section 3 (Bounded Polling).
    """
    total_timeout = polling_cfg.get('total_timeout_sec', 30)
    delay = polling_cfg.get('initial_delay_sec', .25)
    max_delay = polling_cfg.get('max_delay_sec', 3)
    jitter = polling_cfg.get('jitter', True)
    start_time = time.time()

    log(role, f"POLLING for: {url} (timeout: {total_timeout}s)")

    while time.time() - start_time < total_timeout:
        try:
            response = requests.head(url, verify=False, timeout=5) # https enabled for privacy ONLY.
            if response.status_code == 200:
                log(role, f"FOUND: {url}")
                return True
            else:
                log(role, f"Polling {url}: Received status {response.status_code}, will retry.")
        except requests.exceptions.ConnectionError:
            pass  # Expected during startup
        except requests.exceptions.RequestException as e:
            log_err(role, f"WARN: Request error while polling {url}: {e}")

        # Exponential backoff with optional jitter
        current_delay = delay + random.uniform(0, delay * 0.25) if jitter else delay
        time.sleep(current_delay)
        delay = min(delay * 2, max_delay)

    log_err(role, f"TIMEOUT waiting for {url}")
    return False

def extract_bf_from_authorized_keys(path="/root/.ssh/authorized_keys"):
    """
    Extract Boot Factor from SSH authorized_keys (Pattern C).
    This implements the artifact-based IF pattern where the full
    file content becomes the Instance Factor (Section 6).
    """
    try:
        txt = pathlib.Path(path).read_text()
    except FileNotFoundError:
        log_err("ATT", f"FATAL: authorized_keys not found at {path}")
        sys.exit(2)

    # Look for our special comment format: zerosign-bf:<base64url>
    m = re.compile(r"(?:^|\s)zerosign-bf:([A-Za-z0-9_-]+)(?:\s|$)").search(txt)
    if not m:
        log_err("ATT", "FATAL: zerosign-bf:<b64url> token not found")
        sys.exit(2)
    return m.group(1)

def write_error_hmac(path, eca_uuid, bf_b64url, code, role="SYS"):
    """
    Write authenticated error signal (SAE Section 4.4).
    The HMAC binds the error to this specific exchange,
    preventing replay across different ceremonies.
    """
    tag = results_status_hmac.generate({
        "bf_b64url": bf_b64url,
        "eca_uuid": eca_uuid,
        "error_code": code
    })["hmac_hex"]
    write_bytes_atomic(path, tag.encode(), role)

def calculate_jp(bf_b64url, vf_b64url):
    """
    Calculate Joint Possession proof (formal model: calculateJP).
    JP = SHA-256(BF || VF) proves the Attester has both factors.
    This aligns with Section B.4.3 of the ECA draft.
    """
    concat_b64 = concat_b64url.concat({"b64url_list": [bf_b64url, vf_b64url]})["b64url_concat"]
    return sha256_hex.hash_b64url({"msg_b64url": concat_b64})["digest_hex"]

# === Replay Protection (Gate 11) ===
REPLAY_GUARD_DIR = "/results/.replay_guard"

def is_uuid_accepted(eca_uuid):
    """Check if UUID has been previously accepted (replay detection)."""
    guard_file = pathlib.Path(REPLAY_GUARD_DIR) / eca_uuid
    return guard_file.exists()

def mark_uuid_accepted(eca_uuid):
    """
    Mark UUID as accepted (persistent).
    This implements the Accept-Once ceremony requirement
    (Section 3.1 of ECA draft).
    """
    ensure_dir(REPLAY_GUARD_DIR)
    guard_file = pathlib.Path(REPLAY_GUARD_DIR) / eca_uuid
    guard_file.touch()  # Empty file as persistent marker

# ============================================================================
# ATTESTER PROCESS
# Implements the Attester role in the three-phase protocol
# Maps to AttesterProcess in the formal model
# ============================================================================

def attest(args):
    """
    Attester main process - proves identity without credentials.

    This implements the "privileged credential vacuum" where the
    Attester begins with no operational credentials and must prove
    its identity cryptographically to receive them.
    """
    global SCRIPT_START_TIME
    SCRIPT_START_TIME = time.time()
    role = "ATT"

    log(role, "ATTESTER START")

    # Load configuration from manifest
    m = read_yaml(args.manifest)
    eca = os.environ.get("ECA_UUID")

    # Instance Factor is delivered out-of-band (never over the protocol)
    # This maintains separation between what the Verifier knows (BF+IF)
    # and what travels over the network (only proofs)
    session_secret_b64url = os.environ.get("IF_B64URL")
    verifier_pub_b64url = os.environ.get("VERIFIER_PUB_B64URL")

    # Extract BF from authorized_keys (Pattern C implementation)
    bf_b64url = extract_bf_from_authorized_keys()

    # SAE repository paths
    outbox_dir = m["paths"]["attester_to_verifier"]["publish_dir"].replace("${ECA_UUID}", eca)
    verifier_outbox_url = m["paths"]["attester_from_verifier"]["attester_poll_url"].replace("${ECA_UUID}", eca)
    polling_cfg = m["polling"]["attester"]
    ensure_dir(outbox_dir)

    # ========================================================================
    # PHASE 1: Authenticated Channel Setup
    # Formal model: event AttesterInitiates(bf, ifa, uuid)
    # ========================================================================
    log(role, "PHASE 1: Authenticated Channel Setup")

    # Derive ephemeral X25519 keypair deterministically from BF+IF
    # This ensures the same inputs always produce the same keys
    enc_keys = derive_enc_key.derive({
        "bf_b64url": bf_b64url,
        "session_secret_b64url": session_secret_b64url,
        "eca_uuid": eca
    })
    xprivkey_b64url = enc_keys["privkey_b64url"]
    xpubkey_b64url = enc_keys["pubkey_b64url"]

    # Calculate Integrity Hash Beacon: IHB = SHA-256(BF || IF)
    # This binds BF to IF without revealing IF
    ihb_hex = sha256_hex.hash_b64url({
        "msg_b64url": concat_b64url.concat({
            "b64url_list": [bf_b64url, session_secret_b64url]
        })["b64url_concat"]
    })["digest_hex"]

    # Build Phase 1 payload (CBOR encoded)
    phase1_payload_claims = {
        "kem_pub": xpubkey_b64url,  # For Phase 2 encryption
        "ihb": ihb_hex               # Integrity beacon
    }
    phase1_payload_cbor_b64url = eat_encode_cbor.encode({
        "claims": phase1_payload_claims
    })["eat_cbor_b64url"]

    # MAC authenticates the payload using key from BF+IF
    auth_key_b64url = derive_auth_key.derive({
        "bf_b64url": bf_b64url,
        "session_secret_b64url": session_secret_b64url,
        "eca_uuid": eca
    })["auth_key_b64url"]

    phase1_mac_b64url = hmac_sha256.mac({
        "key_b64url": auth_key_b64url,
        "msg_b64url": phase1_payload_cbor_b64url
    })["hmac_b64url"]

    # Publish Phase 1 artifacts with padding
    write_bytes_atomic(f"{outbox_dir}/phase1_payload.cbor",
                      b64d(phase1_payload_cbor_b64url), role, pad_size=2048)
    write_bytes_atomic(f"{outbox_dir}/phase1_mac.b64url",
                      phase1_mac_b64url.encode(), role)
    write_bytes_atomic(f"{outbox_dir}/initial.status", b"", role)  # Signal completion

    # ========================================================================
    # PHASE 2: Receive Validator Factor
    # Formal model: event AttesterUsesNonce(nonce)
    # ========================================================================
    log(role, "PHASE 2: Waiting for Verifier Response")

    # Poll for Verifier's status indicator
    if not poll_for_url(f"{verifier_outbox_url}vf.status", role, polling_cfg):
        sys.exit(1)

    # Retrieve Verifier's proof with retry logic (SAE resilience)
    verifier_proof_cose_bytes = None
    max_retries = 5
    retry_delay = 0.1

    for i in range(max_retries):
        try:
            response = requests.get(f"{verifier_outbox_url}verifier_proof.cose",
                                  verify=False, timeout=5) # https enabled for privacy ONLY.
            response.raise_for_status()
            verifier_proof_cose_bytes = response.content
            log(role, "Fetched verifier_proof.cose successfully.")
            break
        except requests.exceptions.RequestException as e:
            log(role, f"Attempt {i+1}/{max_retries} failed, retrying... ({e})")
            time.sleep(retry_delay)
            retry_delay *= 2

    if verifier_proof_cose_bytes is None:
        log_err(role, f"FATAL: Could not retrieve verifier_proof.cose")
        sys.exit(1)

    # Unpad and verify Verifier's signature
    verifier_proof_cose = unpad_fixed_size(verifier_proof_cose_bytes).decode()

    cose_result = cose_verify1_ed25519.verify({
        "cose_sign1_b64url": verifier_proof_cose,
        "pubkey_b64url": verifier_pub_b64url
    })

    if not cose_result["valid"]:
        log_err(role, "FATAL: Verifier signature invalid")
        sys.exit(1)

    # Extract encrypted VF and nonce
    verifier_payload = eat_decode_cbor.decode({
        "eat_cbor_b64url": cose_result["payload_b64url"]
    })["claims"]

    ciphertext_b64url = verifier_payload["C"]
    vnonce_b64url = verifier_payload["vnonce"]

    # Decrypt using HPKE with AAD binding to ceremony
    # AAD format: eca_uuid || '|' || kem_pub ensures this VF
    # is only valid for this specific ceremony
    aad_bytes = eca.encode('ascii') + b'|' + b64d(xpubkey_b64url)
    aad_b64url = b64url(aad_bytes)

    opened = hpke_open.open_sealed({
        "ciphertext_b64url": ciphertext_b64url,
        "recipient_privkey_b64url": xprivkey_b64url,
        "aad_b64url": aad_b64url,
    })
    plaintext_bytes = b64d(opened["plaintext_b64url"])

    # Split VF||vnonce (32 bytes VF + 16 bytes nonce)
    if len(plaintext_bytes) < 48:
        log_err(role, "FATAL: Phase-2 plaintext too short")
        sys.exit(1)

    vf_bytes = plaintext_bytes[:32]
    vnonce_bytes = plaintext_bytes[32:48]
    vf_b64url = b64url(vf_bytes)

    # Verify nonce consistency (defense in depth)
    if not hmac.compare_digest(b64url(vnonce_bytes), vnonce_b64url):
        log_err(role, "FATAL: Decrypted nonce mismatch")
        sys.exit(1)

    # ========================================================================
    # PHASE 3: Final Proof - Joint Possession
    # Formal model: event AttesterPresentsKey(pubKey)
    # ========================================================================
    log(role, "PHASE 3: Final Evidence and Proof-of-Possession")

    # Derive final identity keypair from BF+VF
    final_keys = derive_composite_key.derive({
        "bf_b64url": bf_b64url,
        "vf_b64url": vf_b64url,
        "eca_uuid": eca
    })
    final_privkey_b64url = final_keys["privkey_b64url"]
    final_pubkey_b64url = final_keys["pubkey_b64url"]

    # EUID = SHA-256(final_pubkey) serves as the identity
    final_attester_id_hex = sha256_hex.hash_b64url({
        "msg_b64url": final_pubkey_b64url
    })["digest_hex"]

    # Joint Possession proof: JP = SHA-256(BF || VF)
    jp_proof_hex = calculate_jp(bf_b64url, vf_b64url)

    # Time claims for EAT
    nbf = int(time.time())
    exp = nbf + int(m["attester"]["lifetime_sec"])

    # Proof-of-Possession tag binds everything together
    # This proves the Attester has both BF and VF
    bound_data = (
        eca.encode('utf-8') +                    # Exchange ID
        bytes.fromhex(ihb_hex) +                 # IHB from Phase 1
        bytes.fromhex(final_attester_id_hex) +   # Final identity
        vnonce_bytes                              # Verifier's nonce
    )
    bound_hash = hashlib.sha256(bound_data).digest()

    mac_key_b64url = derive_mac_key.derive({
        "bf_b64url": bf_b64url,
        "vf_b64url": vf_b64url,
        "eca_uuid": eca
    })["mac_key_b64url"]

    pop_tag_b64url = hmac_sha256.mac({
        "key_b64url": mac_key_b64url,
        "msg_b64url": b64url(bound_hash)
    })["hmac_b64url"]

    # Build final EAT with numeric labels (IANA registered)
    claims = {
        2: final_attester_id_hex,                         # sub: Subject ID
        4: exp,                                           # exp: Expiration
        5: nbf,                                           # nbf: Not before
        6: nbf,                                           # iat: Issued at
        7: eca,                                           # jti: JWT ID (eca_uuid)
        10: b64url(vnonce_bytes),                        # nonce: Freshness
        256: final_attester_id_hex,                      # EUID: ECA identity
        265: "urn:ietf:params:eat:profile:eca-v1",       # Profile identifier
        273: ihb_hex,                                     # Measurements (IHB)
        274: pop_tag_b64url,                              # PoP tag
        275: "attestation",                               # Intended use
        276: jp_proof_hex,                                # JP proof
    }

    # Sign with final identity key
    eat_cbor_b64url = eat_encode_cbor.encode({"claims": claims})["eat_cbor_b64url"]

    cose_sign = cose_sign1_ed25519.sign({
        "payload_b64url": eat_cbor_b64url,
        "privkey_b64url": final_privkey_b64url,
        "kid_b64url": final_pubkey_b64url  # Key ID for verification
    })["cose_sign1_b64url"]

    # Publish final evidence
    write_bytes_atomic(f"{outbox_dir}/evidence.cose",
                      cose_sign.encode(), role, pad_size=2048)
    write_bytes_atomic(f"{outbox_dir}/evidence.status", b"", role)

    log(role, "ATTESTER FINISHED.")

# ============================================================================
# VERIFIER PROCESS
# Implements the Verifier role validating the Attester's proofs
# Maps to VerifierProcess in the formal model
# ============================================================================

def verify(args):
    """
    Verifier main process - validates attestation evidence.

    Enforces the validation gates in strict order as required
    by the formal model to prevent security vulnerabilities.
    """
    global SCRIPT_START_TIME
    SCRIPT_START_TIME = time.time()
    role = "VER"

    log(role, "VERIFIER START")

    # Load configuration and secrets
    m = read_yaml(args.manifest)
    eca = os.environ.get("ECA_UUID")
    results_dir = f"/results/{eca}"
    ensure_dir(results_dir)

    # Verifier knows BF and IF (but never sees them on the wire)
    secrets_dir = f"/secrets/verifier/{eca}"
    bf_b64url = pathlib.Path(secrets_dir, "bf.b64url").read_text().strip()
    session_secret_b64url = pathlib.Path(secrets_dir, "if.b64url").read_text().strip()

    # SAE paths
    outbox_dir = m["paths"]["attester_from_verifier"]["publish_dir"].replace("${ECA_UUID}", eca)
    attester_outbox_url = m["paths"]["attester_to_verifier"]["verifier_poll_url"].replace("${ECA_UUID}", eca)
    polling_cfg = m["polling"]["verifier"]
    ensure_dir(outbox_dir)

    # ========================================================================
    # GATE 11: Replay Protection (must check first)
    # ========================================================================
    if is_uuid_accepted(eca):
        log_err(role, f"GATE 11 FAIL: eca_uuid {eca} already accepted")
        write_error_hmac(f"{results_dir}/results.status", eca, bf_b64url,
                        "IDENTITY_REUSE", role)
        return 1

    # Poll for Phase 1 artifacts
    if not poll_for_url(f"{attester_outbox_url}initial.status", role, polling_cfg):
        write_error_hmac(f"{results_dir}/results.status", eca, bf_b64url,
                        "TIMEOUT", role)
        return 1

    # Retrieve and unpad Phase 1 payload
    phase1_payload_cbor_padded = requests.get(
        f"{attester_outbox_url}phase1_payload.cbor", verify=False).content # https enabled for privacy ONLY.
    phase1_payload_cbor = unpad_fixed_size(phase1_payload_cbor_padded)
    phase1_mac_b64url = requests.get(
        f"{attester_outbox_url}phase1_mac.b64url", verify=False).text.strip() # https enabled for privacy ONLY.

    # ========================================================================
    # GATE 1: MAC Verification
    # Verifies initial authentication using BF+IF
    # ========================================================================
    log(role, "GATE 1: MAC verification")

    auth_key_b64url = derive_auth_key.derive({
        "bf_b64url": bf_b64url,
        "session_secret_b64url": session_secret_b64url,
        "eca_uuid": eca
    })["auth_key_b64url"]

    if not verify_mac.verify({
        "key_b64url": auth_key_b64url,
        "msg_b64url": b64url(phase1_payload_cbor),
        "mac_b64url": phase1_mac_b64url
    })["valid"]:
        write_error_hmac(f"{results_dir}/results.status", eca, bf_b64url,
                        "MAC_INVALID", role)
        return 1

    phase1_payload = eat_decode_cbor.decode({
        "eat_cbor_b64url": b64url(phase1_payload_cbor)
    })["claims"]

    # ========================================================================
    # GATE 2: Instance Authorization
    # In production, check if this IF is authorized for attestation
    # ========================================================================
    log(role, "GATE 2: Instance authorization check")
    # Placeholder - would check against authorized instance list

    # ========================================================================
    # GATE 3: IHB Validation
    # Verifies the Integrity Hash Beacon matches expected value
    # ========================================================================
    log(role, "GATE 3: IHB validation")

    expected_ihb_hex = sha256_hex.hash_b64url({
        "msg_b64url": concat_b64url.concat({
            "b64url_list": [bf_b64url, session_secret_b64url]
        })["b64url_concat"]
    })["digest_hex"]

    if not hmac.compare_digest(expected_ihb_hex, phase1_payload.get("ihb", "")):
        write_error_hmac(f"{results_dir}/results.status", eca, bf_b64url,
                        "IHB_MISMATCH", role)
        return 1

    # ========================================================================
    # GATE 4: KEM Public Key Match
    # Ensures the encryption key matches expected derivation
    # ========================================================================
    log(role, "GATE 4: KEM public key match")

    attester_xpub_b64url = phase1_payload.get("kem_pub", "")
    expected_enc_keys = derive_enc_key.derive({
        "bf_b64url": bf_b64url,
        "session_secret_b64url": session_secret_b64url,
        "eca_uuid": eca
    })

    if not hmac.compare_digest(attester_xpub_b64url, expected_enc_keys["pubkey_b64url"]):
        write_error_hmac(f"{results_dir}/results.status", eca, bf_b64url,
                        "KEM_MISMATCH", role)
        return 1

    # ========================================================================
    # PHASE 2: Generate and Release Validator Factor
    # Formal model: event VFReleased(vf)
    # ========================================================================
    log(role, "PHASE 2: Generating Validator Factor")

    # Generate VF bound to IF (ensures VF secrecy against network attackers)
    vf_seed = os.urandom(16)
    vf_raw = hashlib.sha256(
        vf_seed + b64d(session_secret_b64url) + eca.encode('ascii')
    ).digest()  # 32 bytes

    # Generate fresh nonce for freshness
    vnonce_raw = os.urandom(16)  # exactly 16 bytes
    vnonce_b64url = b64url(vnonce_raw)
    vf_b64url = b64url(vf_raw)
    vnonce_bytes = vnonce_raw  # Keep for later validation

    # Encrypt VF||nonce with HPKE
    plaintext_bytes = vf_raw + vnonce_raw
    plaintext_b64url = b64url(plaintext_bytes)

    # AAD binds the ciphertext to this ceremony
    aad_bytes = eca.encode('ascii') + b'|' + b64d(attester_xpub_b64url)
    aad_b64url = b64url(aad_bytes)

    vf_cipher_b64url = hpke_seal.seal({
        "recipient_pubkey_b64url": attester_xpub_b64url,
        "plaintext_b64url": plaintext_b64url,
        "aad_b64url": aad_b64url
    })["ciphertext_b64url"]

    # Sign the encrypted payload
    v_priv_b64url = pathlib.Path(secrets_dir, "verifier.priv.b64url").read_text().strip()
    v_pub_b64url = ed25519_pubkey_from_priv.derive({
        "privkey_b64url": v_priv_b64url
    })["pubkey_b64url"]

    verifier_payload = {"C": vf_cipher_b64url, "vnonce": vnonce_b64url}
    verifier_cbor_b64url = eat_encode_cbor.encode({
        "claims": verifier_payload
    })["eat_cbor_b64url"]

    verifier_cose = cose_sign1_ed25519.sign({
        "payload_b64url": verifier_cbor_b64url,
        "privkey_b64url": v_priv_b64url,
        "kid_b64url": v_pub_b64url
    })["cose_sign1_b64url"]

    # Publish Phase 2 artifacts
    write_bytes_atomic(f"{outbox_dir}/verifier_proof.cose",
                      verifier_cose.encode(), role, pad_size=2048)
    write_bytes_atomic(f"{outbox_dir}/vf.status", b"", role)

    # Poll for Phase 3 evidence
    if not poll_for_url(f"{attester_outbox_url}evidence.status", role, polling_cfg):
        write_error_hmac(f"{results_dir}/results.status", eca, bf_b64url,
                        "TIMEOUT", role)
        return 1

    # Retrieve final evidence
    evidence_cose_padded = requests.get(
        f"{attester_outbox_url}evidence.cose", verify=False).content # https enabled for privacy ONLY.
    evidence_cose = unpad_fixed_size(evidence_cose_padded).decode().strip()

    # Derive expected final keys for validation
    expected_final_keys = derive_composite_key.derive({
        "bf_b64url": bf_b64url,
        "vf_b64url": vf_b64url,
        "eca_uuid": eca
    })
    expected_final_pubkey_b64url = expected_final_keys["pubkey_b64url"]

    # ========================================================================
    # GATE 5: Time Window Validation
    # Ensures evidence is fresh (within ±60 seconds)
    # ========================================================================
    log(role, "GATE 5: Evidence time window validation")

    try:
        # Preliminary verification to extract claims
        cose_preliminary = cose_verify1_ed25519.verify({
            "cose_sign1_b64url": evidence_cose,
            "pubkey_b64url": expected_final_pubkey_b64url
        })

        if cose_preliminary["valid"]:
            preliminary_claims = eat_decode_cbor.decode({
                "eat_cbor_b64url": cose_preliminary["payload_b64url"]
            })["claims"]

            now = int(time.time())
            iat = preliminary_claims.get(6, 0)
            nbf = preliminary_claims.get(5, 0)
            exp = preliminary_claims.get(4, 0)

            # Check monotonic ordering
            if not (iat <= nbf <= exp):
                log_err(role, "GATE 5 FAIL: Time claims not monotonic")
                write_error_hmac(f"{results_dir}/results.status", eca, bf_b64url,
                                "TIME_EXPIRED", role)
                return 1

            # Check time skew
            if abs(now - iat) > 60:
                log_err(role, f"GATE 5 FAIL: iat {iat} outside window")
                write_error_hmac(f"{results_dir}/results.status", eca, bf_b64url,
                                "TIME_EXPIRED", role)
                return 1

            # Check expiration
            if now > exp:
                log_err(role, f"GATE 5 FAIL: Evidence expired")
                write_error_hmac(f"{results_dir}/results.status", eca, bf_b64url,
                                "TIME_EXPIRED", role)
                return 1
    except:
        pass  # Will fail in Gate 7 if signature invalid

    # ========================================================================
    # GATE 7: Signature Verification
    # Verifies the final evidence signature
    # ========================================================================
    log(role, "GATE 7: Evidence signature verification")

    cose_result = cose_verify1_ed25519.verify({
        "cose_sign1_b64url": evidence_cose,
        "pubkey_b64url": expected_final_pubkey_b64url
    })

    if not cose_result["valid"]:
        write_error_hmac(f"{results_dir}/results.status", eca, bf_b64url,
                        "SIG_INVALID", role)
        return 1

    claims = eat_decode_cbor.decode({
        "eat_cbor_b64url": cose_result["payload_b64url"]
    })["claims"]

    # ========================================================================
    # GATE 6: Schema Validation
    # Ensures all required claims are present with correct types
    # ========================================================================
    log(role, "GATE 6: Evidence schema compliance")

    required_claims = [2, 4, 5, 6, 10, 256, 265, 273, 274, 275, 276]
    for claim in required_claims:
        if claim not in claims:
            log_err(role, f"GATE 6 FAIL: Missing claim {claim}")
            write_error_hmac(f"{results_dir}/results.status", eca, bf_b64url,
                            "SCHEMA_ERROR", role)
            return 1

    # Validate profile
    if claims.get(265) != "urn:ietf:params:eat:profile:eca-v1":
        log_err(role, "GATE 6 FAIL: Invalid eat_profile")
        write_error_hmac(f"{results_dir}/results.status", eca, bf_b64url,
                        "SCHEMA_ERROR", role)
        return 1

    # ========================================================================
    # GATE 8: Nonce Match
    # Proves freshness by verifying the Verifier's nonce
    # Formal model: AttesterUsesNonce event
    # ========================================================================
    log(role, "GATE 8: Nonce verification")

    received_nonce_b64url = claims.get(10, "")
    received_nonce = b64d(received_nonce_b64url)

    if not hmac.compare_digest(vnonce_bytes, received_nonce):
        log_err(role, "GATE 8 FAIL: Nonce mismatch")
        write_error_hmac(f"{results_dir}/results.status", eca, bf_b64url,
                        "NONCE_MISMATCH", role)
        return 1

    # ========================================================================
    # GATE 9: JP (Joint Possession) Validation
    # Verifies the Attester possesses both BF and VF
    # Formal model: VerifierValidatesWithKey event
    # ========================================================================
    log(role, "GATE 9: JP (Joint Possession) validation")

    expected_jp_proof_hex = calculate_jp(bf_b64url, vf_b64url)
    received_jp_proof_hex = claims.get(276, "")

    if not hmac.compare_digest(expected_jp_proof_hex, received_jp_proof_hex):
        write_error_hmac(f"{results_dir}/results.status", eca, bf_b64url,
                        "KEY_BINDING_INVALID", role)
        return 1

    # ========================================================================
    # GATE 10: PoP (Proof of Possession) Validation
    # Final cryptographic proof binding all elements
    # Formal model: VerifierAccepts event
    # ========================================================================
    log(role, "GATE 10: PoP (Proof of Possession) validation")

    euid_hex = claims.get(256, "")
    ihb_hex = claims.get(273, "")

    expected_bound_data = (
        eca.encode('utf-8') +
        bytes.fromhex(ihb_hex) +
        bytes.fromhex(euid_hex) +
        vnonce_bytes
    )
    expected_bound_hash = hashlib.sha256(expected_bound_data).digest()

    mac_key_b64url = derive_mac_key.derive({
        "bf_b64url": bf_b64url,
        "vf_b64url": vf_b64url,
        "eca_uuid": eca
    })["mac_key_b64url"]

    expected_pop_tag_b64url = hmac_sha256.mac({
        "key_b64url": mac_key_b64url,
        "msg_b64url": b64url(expected_bound_hash)
    })["hmac_b64url"]

    received_pop_tag_b64url = claims.get(274, "")

    if not hmac.compare_digest(expected_pop_tag_b64url, received_pop_tag_b64url):
        write_error_hmac(f"{results_dir}/results.status", eca, bf_b64url,
                        "POP_INVALID", role)
        return 1

    # ========================================================================
    # SUCCESS: All gates passed
    # Mark UUID as accepted and generate Attestation Result
    # ========================================================================
    mark_uuid_accepted(eca)  # Persistent replay protection

    log(role, "All gates passed. VERDICT: SUCCESS.")

    now = int(time.time())

    # Generate Attestation Result (AR) with IANA-registered claims
    result_claims = {
        1: "verifier-instance-001",                      # iss: Issuer
        2: claims.get(2),                                 # sub: Subject (EUID)
        7: eca,                                           # jti: JWT ID
        6: now,                                           # iat: Issued at
        5: now,                                           # nbf: Not before
        4: now + 300,                                     # exp: Expiration
        -262148: "urn:ietf:params:rats:status:success"   # RATS status
    }

    result_eat = eat_encode_cbor.encode({"claims": result_claims})["eat_cbor_b64url"]

    result_cose = cose_sign1_ed25519.sign({
        "payload_b64url": result_eat,
        "privkey_b64url": v_priv_b64url,
        "kid_b64url": v_pub_b64url
    })["cose_sign1_b64url"]

    # Write AR first, then status (atomicity requirement)
    write_bytes_atomic(f"{results_dir}/results.cose.b64url",
                      result_cose.encode(), role)
    write_bytes_atomic(f"{results_dir}/results.status", b"", role)  # Success signal

    return 0

def decode_ar(args):
    """
    Decode and verify an Attestation Result.
    Used for validating the final output of successful attestation.
    """
    role = "AR-DECODE"
    log(role, "Starting Attestation Result decoding...")

    try:
        eca_uuid = os.environ["ECA_UUID"]
        pub_b64u = os.environ["VERIFIER_PUB_B64URL"]
        cose_path = f"/results/{eca_uuid}/results.cose.b64url"

        log(role, f"Reading AR from: {cose_path}")
        cose_b64u = pathlib.Path(cose_path).read_text().strip()

        if not cose_b64u:
            log_err(role, "FATAL: Attestation Result file is empty.")
            return 1

        res = cose_verify1_ed25519.verify({
            "cose_sign1_b64url": cose_b64u,
            "pubkey_b64url": pub_b64u
        })

        if not res.get("valid"):
            log_err(role, "FATAL: COSE signature verification failed.")
            return 1

        log(role, "COSE signature VERIFIED.")

        payload_b64u = res.get("payload_b64url")
        claims = eat_decode_cbor.decode({
            "eat_cbor_b64url": payload_b64u
        }).get("claims")

        print("--- DECODED ATTESTATION RESULT ---")
        print(json.dumps(claims, indent=2, sort_keys=True))
        print("----------------------------------")

        return 0

    except FileNotFoundError:
        log_err(role, f"FATAL: Could not find Attestation Result at {cose_path}")
        return 1
    except Exception as e:
        log_err(role, f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1

def main():
    """
    Main entry point for the ECA CLI.
    Supports three commands: attest, verify, decode-ar
    """
    ap = argparse.ArgumentParser(
        prog="zerosign",
        description="CLI for Ephemeral Compute Attestation (ECA) PoC."
    )

    sub = ap.add_subparsers(dest="cmd", required=True)

    # Attester command
    p_attest = sub.add_parser("attest", help="Run the Attester role.")
    p_attest.add_argument("--manifest", required=True,
                         help="Path to manifest YAML file")
    p_attest.set_defaults(func=attest)

    # Verifier command
    p_verify = sub.add_parser("verify", help="Run the Verifier role.")
    p_verify.add_argument("--manifest", required=True,
                         help="Path to manifest YAML file")
    p_verify.set_defaults(func=verify)

    # AR decoder command
    p_decode = sub.add_parser("decode-ar",
                             help="Decode an Attestation Result.")
    p_decode.set_defaults(func=decode_ar)

    args = ap.parse_args()
    sys.exit(args.func(args) or 0)

if __name__ == "__main__":
    main()
