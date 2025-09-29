#!/usr/bin/env python3
import sys, re, json, base64, os
path = sys.argv[1] if len(sys.argv) > 1 else "/root/.ssh/authorized_keys"
try:
    with open(path, "r", encoding="utf-8") as f:
        s = f.read()
except FileNotFoundError:
    print(json.dumps({"found": False, "bf_b64url": ""})); sys.exit(0)
m = re.search(r"zerosign-bf:([A-Za-z0-9_-]+)", s)
if not m:
    print(json.dumps({"found": False, "bf_b64url": ""})); sys.exit(0)
print(json.dumps({"found": True, "bf_b64url": m.group(1)}))
