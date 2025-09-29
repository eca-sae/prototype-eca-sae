#!/bin/bash
set -Eeuo pipefail

# --- Graceful Shutdown Logic ---

# Define a cleanup function to be called on shutdown
cleanup() {
    echo "[ATT] Received shutdown signal. Shutting down web server..."
    # Kill the web server process gracefully
    kill "${SERVER_PID}"
    # Wait for it to terminate
    wait "${SERVER_PID}" 2>/dev/null
    echo "[ATT] Cleanup complete. Exiting."
    exit 0
}

# Set the trap to call the cleanup function on SIGTERM or SIGINT
trap cleanup SIGTERM SIGINT

# --- Main Entrypoint Logic ---

# Announce network identity and target
echo "[ATT-DIAG] My Hostname: $(hostname), IP: $(hostname -i)"
POLL_URL=$(/opt/venv/bin/python3 -c "import yaml; print(yaml.safe_load(open('/run/manifest.yml'))['paths']['attester_from_verifier']['attester_poll_url'])")
echo "[ATT-DIAG] Configured to poll Verifier at: ${POLL_URL}"
echo "---"

# Setup directories
mkdir -p /root/.wellknown

# Start the HTTPS server in the background and capture its PID
/app/run_https_static.sh --root /root/.wellknown --port 8443 --self-signed &
SERVER_PID=$!
echo "[ATT] Web server started with PID ${SERVER_PID}."

# Run the main attestation process
/opt/venv/bin/python -m zerosign attest --manifest /run/manifest.yml

# Wait indefinitely for the background web server. The script will block here
# until the 'trap' function is triggered by a signal and kills the server.
echo "[ATT] Attestation process finished. Waiting for shutdown signal..."
wait "${SERVER_PID}"
