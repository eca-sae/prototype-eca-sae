#!/usr/bin/env python3
"""
manifest_validate.py — sanity checks for the run manifest (enhanced).

Checks:
- required top-level keys
- profile is in allowed set (e.g., MTI)
- polling bounds for attester and verifier (SAE-friendly):
    * initial_delay > 0
    * max_delay >= initial_delay
    * timeout >= max_delay
- verifier.ephemeral_keys_only == true
- vf block presence and fields
"""
from __future__ import annotations
import sys, json, yaml, os
from .common import write_json

SCHEMA_PATH = "/app/schemas/manifest.schema.json"

def _check_polling(name, p, errors):
    if not isinstance(p, dict):
        errors.append(f"polling:{name}:not_object"); return
    ini = p.get("initial_delay", 1.0)
    mx  = p.get("max_delay", 32.0)
    to  = p.get("timeout", 60.0)
    if ini <= 0: errors.append(f"polling:{name}:initial_delay")
    if mx  < ini: errors.append(f"polling:{name}:max_delay")
    if to  < mx:  errors.append(f"polling:{name}:timeout")

def main():
    if not os.path.exists(SCHEMA_PATH):
        print(f"error: schema not found at {SCHEMA_PATH}", file=sys.stderr); sys.exit(2)
    schema = json.load(open(SCHEMA_PATH, "r"))
    profile_enum = set(schema.get("profile_enum", []))

    data = json.load(sys.stdin)
    path = data.get("manifest_path")
    if not path:
        print("error: manifest_path required", file=sys.stderr); sys.exit(2)

    with open(path, "r") as f:
        m = yaml.safe_load(f)

    errors = []
    for k in schema.get("required", []):
        if k not in m:
            errors.append(f"missing:{k}")

    mode = m.get("mode")
    if mode not in schema.get("mode_enum", []):
        errors.append("mode:value")

    if m.get("verifier", {}).get("ephemeral_keys_only") is not True:
        errors.append("verifier.ephemeral_keys_only")

    if m.get("profile") not in profile_enum:
        errors.append("profile:value")

    vf = m.get("vf", {})
    for k in ["delivery","encryption","plaintext_len_bytes","channel_path"]:
        if k not in vf:
            errors.append(f"vf:missing:{k}")

    # Polling checks
    pol = m.get("polling", {})
    _check_polling("attester", pol.get("attester", {}), errors)
    _check_polling("verifier", pol.get("verifier", {}), errors)

    ok = len(errors) == 0
    write_json({"ok": ok, "errors": errors})
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
