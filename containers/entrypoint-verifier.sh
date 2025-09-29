#!/bin/bash
set -Eeuo pipefail

# Announce network identity and target
echo "[VER-DIAG] My Hostname: $(hostname), IP: $(hostname -i)"
POLL_URL=$(/opt/venv/bin/python3 -c "import yaml; print(yaml.safe_load(open('/run/manifest.yml'))['paths']['attester_to_verifier']['verifier_poll_url'])")
echo "[VER-DIAG] Configured to poll Attester at: ${POLL_URL}"
echo "---"

# Run the main verification process
/opt/venv/bin/python -m zerosign verify --manifest /run/manifest.yml
