#!/bin/bash
set -euo pipefail

# Announce network identity
echo "[MOCK-S3-DIAG] My Hostname: $(hostname), IP: $(hostname -i)"
echo "---"

# This script acts as a simple static file server.
# It prefers the custom HTTPS server script but falls back to busybox httpd.

echo "[MOCK-S3] Starting custom HTTPS server on port 443..."
/app/run_https_static.sh --root /S3 --port 443 --self-signed
