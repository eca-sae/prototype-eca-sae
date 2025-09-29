#!/usr/bin/env python3
import sys, json, hashlib, base64
path = sys.argv[1] if len(sys.argv) > 1 else "/root/.ssh/authorized_keys"
with open(path, "rb") as f:
    data = f.read()
ihb = hashlib.sha512(data).hexdigest()
print(json.dumps({"ihb_sha512_hex": ihb, "bytes_len": len(data)}))
