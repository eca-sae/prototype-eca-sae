#!/usr/bin/env python3
"""
Converts an Instance Factor string (e.g., a cloud instance ID) to the
base64url-encoded raw bytes required for IHB computation, using the
normative UTF-8 encoding rule.
"""
import sys
import json
import base64

def write_json(obj):
    """Writes a JSON object to stdout."""
    json.dump(obj, sys.stdout, separators=(",", ":"))
    sys.stdout.write("\n")

def b64url_encode(b: bytes) -> str:
    """Encodes bytes to unpadded base64url."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

try:
    data = json.load(sys.stdin)
    if_string = data.get("if_string")
    if not if_string:
        raise ValueError("Input JSON must contain 'if_string' key")

    # Per the normative rule, convert the string to raw bytes using UTF-8
    if_raw_bytes = if_string.encode("utf-8")
    if_b64url = b64url_encode(if_raw_bytes)

    write_json({"if_b64url": if_b64url})

except (json.JSONDecodeError, ValueError) as e:
    print(f"Error: {e}", file=sys.stderr)
    sys.exit(1)
    