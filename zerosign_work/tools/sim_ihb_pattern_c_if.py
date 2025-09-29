#!/usr/bin/env python3
import os, json, base64
AIK = os.urandom(32)
b64url = base64.urlsafe_b64encode(AIK).rstrip(b"=").decode("ascii")
print(json.dumps({"if_b64url": b64url}))
