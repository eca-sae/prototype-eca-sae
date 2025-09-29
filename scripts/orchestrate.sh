#!/usr/bin/env bash
#
# orchestrate.sh - Project ZeroSign - Prototype implementation for ECA/SAE
# ============================================================================
# Copyright 2025 Nathanael Ritz
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# ============================================================================
#
# This script orchestrates the complete ECA attestation ceremony using Docker
# containers to simulate ephemeral compute instances and verifiers.
#
# Architecture:
#   - Attester containers: Ephemeral VMs with no initial credentials
#   - Verifier containers: Validation services with BF+IF knowledge
#   - Mock S3: SAE repository for artifact exchange
#   - Shared volumes: Secrets distribution and result storage
#
# Workflow (maps to protocol phases):
#   1. Generate cryptographic materials (BF, IF, verifier keys)
#   2. Provision secrets to appropriate volumes
#   3. Launch containers in parallel
#   4. Monitor attestation progress
#   5. Validate and decode Attestation Results
#
# Security Notes:
#   - BF is injected via SSH authorized_keys (Pattern C)
#   - IF is delivered out-of-band via environment variables
#   - Verifier keys are ephemeral per ceremony (Section 4.6.1)
#   - Results are persisted for audit trail

set -euo pipefail  # Strict error handling

# ============================================================================
# Helper Functions
# ============================================================================

# Color-coded output for clarity
err()  { printf "\e[31m[ERR]\e[0m %s\n"  "$*" >&2; }
info() { printf "\e[36m[INFO]\e[0m %s\n" "$*"; }
note() { printf "\e[35m[ORCH]\e[0m %s\n" "$*"; }

# Generate UUID v4 for unique ceremony identification
# Each attestation gets a unique eca_uuid (Section 3.1 requirement)
uuid4() {
  if command -v python3 >/dev/null 2>&1; then
    python3 -c 'import uuid; print(uuid.uuid4())'
  elif command -v uuidgen >/dev/null 2>&1; then
    uuidgen
  else
    err "Need python3 or uuidgen to mint a UUIDv4"
    exit 1
  fi
}

# ============================================================================
# Global Configuration
# ============================================================================

SHOW_AR="${SHOW_AR:-0}"              # Flag to display decoded ARs
PARALLEL_RUNS="${PARALLEL_RUNS:-1}"  # Number of parallel attestations
RESULTS_VOL="zsn_attestation_results"
VERIFIER_IMAGE_DEFAULT="zerosign/verifier:bookworm"
WORKDIR_ROOT="$(pwd)/_runs"
AR_QUEUE_FILE="${WORKDIR_ROOT}/.ar_queue"

# ============================================================================
# Docker Volume Helpers (no sudo required)
# ============================================================================

# Test if file exists in Docker volume
_vol_test() {
  local rel="$1"
  docker run --rm -v "${RESULTS_VOL}:/results:ro" busybox:1.36.1 \
    sh -c "[ -f '/results/${rel}' ]"
}

# Test if file exists and is non-empty
_vol_test_s() {
  local rel="$1"
  docker run --rm -v "${RESULTS_VOL}:/results:ro" busybox:1.36.1 \
    sh -c "[ -s '/results/${rel}' ]"
}

# Read first 128 bytes of file (for error diagnosis)
_vol_cat_head() {
  local rel="$1"
  docker run --rm -v "${RESULTS_VOL}:/results:ro" busybox:1.36.1 \
    sh -c "head -c 128 '/results/${rel}' || true"
}

# ============================================================================
# Attestation Result Decoder
# Uses the verifier container to decode and verify ARs
# ============================================================================
decode_and_print_ar() {
  local eca_uuid="$1"
  local verifier_pub_b64url="$2"

  note "[AR] Verifying & decoding Attestation Result for ${eca_uuid}…"

  docker run --rm \
    --entrypoint /bin/bash \
    -v "${RESULTS_VOL}:/results:ro" \
    -e "VERIFIER_PUB_B64URL=${verifier_pub_b64url}" \
    -e "ECA_UUID=${eca_uuid}" \
    -e "PYTHONPATH=/app" \
    "${VERIFIER_IMAGE_DEFAULT}" \
    -c "/opt/venv/bin/python -m zerosign decode-ar"
}

# ============================================================================
# Main Attestation Function
# Executes a complete attestation ceremony for one instance
# ============================================================================
run_attestation() {
  local RUN_INDEX="$1"     # For parallel run identification
  local MODE="$2"           # deterministic or randomized
  local START_TIME=$SECONDS

  local ECA_UUID="$(uuid4)"
  local ECA_UUID_SHORT="$(printf '%s' "$ECA_UUID" | cut -c1-8)"
  local PROJECT="zs-${ECA_UUID_SHORT}"

  log() { printf "[RUN %s] %s\n" "$RUN_INDEX" "$*"; }
  log "STARTING (${MODE}): eca_uuid=${ECA_UUID}"

  # Create run-specific directory structure
  local RUN_DIR_ABS="$(pwd)/_runs/${ECA_UUID}"
  mkdir -p "$RUN_DIR_ABS"
  local RUN_MANIFEST_PATH="${RUN_DIR_ABS}/manifest.yml"
  local RUN_ENV_FILE="${RUN_DIR_ABS}/.env"
  local AUTHORIZED_KEYS_PATH="${RUN_DIR_ABS}/authorized_keys"

  # ========================================================================
  # Generate Verifier Keys (ephemeral per ceremony - Section 4.6.1)
  # ========================================================================
  local VERIFIER_IMAGE="zerosign/verifier:bookworm"
  local VERIFIER_KEYS=$(docker run --rm --entrypoint="" "${VERIFIER_IMAGE}" \
    /opt/venv/bin/python3 -c '
import json, base64, sys
from cryptography.hazmat.primitives.asymmetric import ed25519

def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

try:
    sk = ed25519.Ed25519PrivateKey.generate()
    pk = sk.public_key()
    priv_raw = sk.private_bytes_raw()
    pub_raw = pk.public_bytes_raw()
    print(json.dumps({
        "privkey_b64url": b64u(priv_raw),
        "pubkey_b64url":  b64u(pub_raw)
    }))
except Exception as e:
    print(f"Key generation failed: {e}", file=sys.stderr)
    sys.exit(1)
')

  if [[ -z "$VERIFIER_KEYS" ]]; then
    log "\e[31mFAIL\e[0m: Failed to generate verifier keys."
    return 1
  fi

  local VERIFIER_PRIV_B64URL=$(echo "$VERIFIER_KEYS" | jq -r .privkey_b64url)
  local VERIFIER_PUB_B64URL=$(echo "$VERIFIER_KEYS" | jq -r .pubkey_b64url)

  # Calculate fingerprint for debugging
  local VFP_HASH_B64=$(printf '%s' "$VERIFIER_PUB_B64URL" | python3 -c '
import base64, sys, hashlib
raw_pub = base64.urlsafe_b64decode(sys.stdin.read() + "===")
hash_b64 = base64.b64encode(hashlib.sha256(raw_pub).digest()).decode("ascii")
print(hash_b64.rstrip("="))
')
  local VERIFIER_FINGERPRINT="SHA256:${VFP_HASH_B64}"

  # Store verifier private key in secrets volume
  docker run --rm -v "zsn_verifier_secrets:/secrets" busybox:1.36.1 sh -c \
    "mkdir -p /secrets/verifier/${ECA_UUID} && \
     printf '%s' \"${VERIFIER_PRIV_B64URL}\" > \
     /secrets/verifier/${ECA_UUID}/verifier.priv.b64url" >/dev/null

  # ========================================================================
  # Generate Boot Factor and Instance Factor
  # ========================================================================
  local BF_B64URL IF_B64URL VNONCE_B64URL

  if [[ "$MODE" == "deterministic" ]]; then
    # Fixed values for reproducible testing
    BF_B64URL="Be80sHHnLhyYH/koGgKTFA"
    local IF_STRING="i-d81a9787e91d516d"

    # Simulate IF derivation
    IF_B64URL=$(printf '{"if_string":"%s"}' "$IF_STRING" | \
      docker run --rm -i --entrypoint="" \
      -v "$(pwd)":/app:ro ${VERIFIER_IMAGE} \
      /opt/venv/bin/python /app/zerosign_work/tools/sim_ihb_pattern_b_if.py | \
      jq -r .if_b64url)

    VNONCE_B64URL="z3x9v8b7n6m5l4k3j2h1g0"
  else
    # Random values for production-like testing
    BF_B64URL=$(openssl rand 32 | openssl base64 -A | tr '+/' '-_' | tr -d '=')
    IF_B64URL=$(openssl rand 16 | openssl base64 -A | tr '+/' '-_' | tr -d '=')
    VNONCE_B64URL=""
  fi

  # Store BF and IF in verifier secrets
  docker run --rm -v "zsn_verifier_secrets:/secrets" busybox:1.36.1 sh -c \
    "printf '%s' \"${BF_B64URL}\" > /secrets/verifier/${ECA_UUID}/bf.b64url && \
     printf '%s' \"${IF_B64URL}\" > /secrets/verifier/${ECA_UUID}/if.b64url" \
    >/dev/null

  # ========================================================================
  # Prepare SSH Key with embedded BF (Pattern C implementation)
  # The BF is embedded as a comment in the authorized_keys file
  # ========================================================================
  ssh-keygen -t ed25519 -N "" -f "${RUN_DIR_ABS}/id_ed25519" >/dev/null 2>&1
  local PUB_KEY="$(cut -d' ' -f1,2 "${RUN_DIR_ABS}/id_ed25519.pub")"

  # Format: <pubkey> zerosign-bf:<BF> <comment>
  echo "${PUB_KEY} zerosign-bf:${BF_B64URL} attester@vm" > "$AUTHORIZED_KEYS_PATH"
  chmod 600 "$AUTHORIZED_KEYS_PATH"

  # Generate manifest from template
  ZSN_MODE="$MODE" \
    ECA_UUID="$ECA_UUID" \
    ECA_UUID_SHORT="$ECA_UUID_SHORT" \
    VERIFIER_FINGERPRINT="$VERIFIER_FINGERPRINT" \
    envsubst < examples/manifest.pattern_b.yml > "$RUN_MANIFEST_PATH"

  # Create environment file for Docker Compose
  cat > "$RUN_ENV_FILE" << EOF
ECA_UUID=${ECA_UUID}
ECA_UUID_SHORT=${ECA_UUID_SHORT}
VERIFIER_PUB_B64URL=${VERIFIER_PUB_B64URL}
VERIFIER_FINGERPRINT=${VERIFIER_FINGERPRINT}
IF_B64URL=${IF_B64URL}
VNONCE_B64URL=${VNONCE_B64URL}
ZSN_NET_NAME=${ZSN_NET_NAME:-zs-pocnet}
RUN_MANIFEST_PATH=${RUN_MANIFEST_PATH}
AUTHORIZED_KEYS_PATH=${AUTHORIZED_KEYS_PATH}
EOF

  # ========================================================================
  # Launch Docker Containers
  # Attester and Verifier run in parallel, communicating via SAE
  # ========================================================================
  log "Launching containers in detached mode..."
  docker compose -p "$PROJECT" \
    --env-file "$RUN_ENV_FILE" \
    -f containers/compose.app.yaml \
    up -d --force-recreate

  # Monitor logs in background
  log "Watching logs and waiting for result file..."
  docker compose -p "$PROJECT" logs -f &
  LOGS_PID=$!

  # ========================================================================
  # Poll for Attestation Result
  # Success: empty status file (SAE convention)
  # Failure: non-empty status file with HMAC error code
  # ========================================================================
  local RESULT_REL_PATH="${ECA_UUID}/results.status"
  local TOTAL_TIMEOUT=75
  local POLLING_START_TIME=$SECONDS

  while true; do
    if _vol_test "$RESULT_REL_PATH"; then
      log "Result file found."
      break
    fi

    if (( SECONDS - POLLING_START_TIME > TOTAL_TIMEOUT )); then
      log "\e[31mFAIL\e[0m: Timed out waiting for result file."
      kill $LOGS_PID
      return 1
    fi

    sleep 1
  done

  kill $LOGS_PID 2>/dev/null || true

  # ========================================================================
  # Check Result Status
  # Empty file = success, non-empty = failure with error code
  # ========================================================================
  if _vol_test_s "$RESULT_REL_PATH"; then
    # Non-empty = failure
    local ELAPSED_TIME=$((SECONDS - START_TIME))

    # Attempt to classify the error
    local ERROR_CODE=$(./zerosign_work/tools/classify_error.sh "$ECA_UUID" 2>/dev/null | \
      grep 'Classified verifier error' | \
      awk -F' – ' '{print $1}' | \
      awk -F': ' '{print $2}' || echo "UNKNOWN")

    log "VERDICT: *FAILED* - ${ERROR_CODE} (${ELAPSED_TIME}s)"

    # Show error HMAC for debugging
    note "[DBG] results.status head: $(_vol_cat_head "$RESULT_REL_PATH")"
    echo ""
    return 1
  else
    # Empty = success
    local ELAPSED_TIME=$((SECONDS - START_TIME))
    log "VERDICT: *PASSED* (${ELAPSED_TIME}s)"

    local AR_REL_PATH="${ECA_UUID}/results.cose.b64url"
    info "Signed AR (volume:${RESULTS_VOL}): /results/${AR_REL_PATH}"

    # Wait for AR to be written (avoid race condition)
    local waited=0
    for _ in $(seq 1 50); do  # up to ~10s
      if _vol_test_s "$AR_REL_PATH"; then
        break
      fi
      sleep 0.2
      waited=$((waited+1))
    done

    if ! _vol_test_s "$AR_REL_PATH"; then
      note "[AR] Still missing or empty after wait: /results/${AR_REL_PATH}"
    elif (( waited > 0 )); then
      note "[AR] Ready after ~$((waited*200))ms."
    fi

    # Handle AR decoding based on run mode
    if [[ "${PARALLEL_RUNS}" == "1" ]]; then
      # Single run: decode immediately
      if _vol_test_s "$AR_REL_PATH" && [[ -n "${VERIFIER_PUB_B64URL:-}" ]]; then
        decode_and_print_ar "${ECA_UUID}" "${VERIFIER_PUB_B64URL}"
        echo
      else
        if [[ -z "${VERIFIER_PUB_B64URL:-}" ]]; then
          note "[AR] Skipping decode (no VERIFIER_PUB_B64URL present)."
        else
          note "[AR] Skipping decode (AR not found or empty)."
        fi
      fi
    else
      # Multi-run: queue for batch decoding
      if [[ "${SHOW_AR}" == "1" ]]; then
        mkdir -p "${WORKDIR_ROOT}"
        printf "%s|%s\n" "${ECA_UUID}" "${VERIFIER_PUB_B64URL:-}" >> "${AR_QUEUE_FILE}"
      fi
    fi

    return 0
  fi
}

# ============================================================================
# Main Orchestration Logic
# ============================================================================
main() {
  local parallel_runs=1
  local MODE="randomized"
  local BUILD_FLAGS=""

  # Parse command-line arguments
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --parallel)
        parallel_runs="$2"
        shift 2
        ;;
      --show-ar)
        SHOW_AR=1
        shift
        ;;
      deterministic|randomized)
        MODE="$1"
        shift
        ;;
      --rebuild)
        BUILD_FLAGS="--no-cache"
        shift
        ;;
      *)
        err "Unknown argument: $1"
        exit 2
        ;;
    esac
  done

  PARALLEL_RUNS="$parallel_runs"

  # Validate configuration
  if [[ "$MODE" == "deterministic" && "$parallel_runs" -gt 1 ]]; then
    err "Cannot run 'deterministic' mode with '--parallel > 1'. Use 'randomized'."
    exit 1
  fi

  note "Performing initial setup..."

  # ========================================================================
  # Network and Volume Setup
  # Creates isolated Docker network and persistent volumes
  # ========================================================================
  local net_name="${ZSN_NET_NAME:-zs-pocnet}"

  if ! docker network inspect "$net_name" >/dev/null 2>&1; then
    info "Creating fixed network: $net_name"
    docker network create --driver bridge --subnet "172.29.250.0/24" "$net_name" >/dev/null
  fi

  # Create required volumes if they don't exist
  for vol in zsn_attester_secrets zsn_verifier_secrets zsn_attestation_results \
             zsn_vf_channel zsn_s3_bucket; do
    if ! docker volume inspect "$vol" >/dev/null 2>&1; then
      info "Creating external volume: $vol"
      docker volume create "$vol" >/dev/null
    fi
  done

  # Clean up any stray containers from previous runs
  note "Cleaning up any stray attester/verifier containers from previous runs..."
  local STRAY_CONTAINERS
  STRAY_CONTAINERS=$(docker ps -a \
    --filter "name=attester-" \
    --filter "name=verifier-" -q)

  if [[ -n "$STRAY_CONTAINERS" ]]; then
    info "Removing stray containers..."
    docker rm -f $STRAY_CONTAINERS >/dev/null
  fi

  # ========================================================================
  # Build Docker Images
  # Creates attester and verifier container images
  # ========================================================================
  note "Building Docker images..."

  # Set dummy environment variables for build
  export ECA_UUID="buildtime" ECA_UUID_SHORT="buildtime"
  export RUN_MANIFEST_PATH="/dev/null" AUTHORIZED_KEYS_PATH="/dev/null"
  export IF_B64URL="" VERIFIER_PUB_B64URL="" VERIFIER_FINGERPRINT="" VNONCE_B64URL=""

  docker compose -f containers/compose.app.yaml build ${BUILD_FLAGS}

  # ========================================================================
  # Start Mock S3 Service (SAE Repository)
  # Provides the artifact exchange mechanism
  # ========================================================================
  note "Ensuring a fresh mock-s3 service is running..."

  info "Tearing down any existing mock-s3 service to ensure a clean state..."
  docker compose -f containers/compose.shared.yaml down --remove-orphans >/dev/null 2>&1 || true

  info "Starting fresh mock-s3 service..."
  docker compose -f containers/compose.shared.yaml up -d --build

  # Clear AR queue for this run
  mkdir -p "${WORKDIR_ROOT}"
  : > "${AR_QUEUE_FILE}"

  # ========================================================================
  # Launch Parallel Attestations
  # Each run is independent with its own eca_uuid
  # ========================================================================
  note "Launching ${parallel_runs} parallel attestation(s) in '${MODE}' mode..."

  pids=()
  for i in $(seq 1 "$parallel_runs"); do
    run_attestation "$i" "$MODE" &
    pids+=($!)
  done

  # Wait for all attestations to complete
  final_exit_code=0
  for pid in "${pids[@]}"; do
    if ! wait "$pid"; then
      final_exit_code=1
    fi
  done

  # ========================================================================
  # Batch AR Decoding (for multi-run with --show-ar)
  # ========================================================================
  if [[ "${parallel_runs}" -gt 1 && "${SHOW_AR}" == "1" && -s "${AR_QUEUE_FILE}" ]]; then
    note "Decoding Attestation Results (--show-ar)…"

    while IFS="|" read -r q_uuid q_pub; do
      # Try to load pubkey from run env if not queued
      if [[ -z "${q_pub}" && -f "${WORKDIR_ROOT}/${q_uuid}/.env" ]]; then
        # shellcheck disable=SC1090
        source "${WORKDIR_ROOT}/${q_uuid}/.env"
        q_pub="${VERIFIER_PUB_B64URL:-}"
      fi

      if [[ -n "${q_pub}" ]]; then
        decode_and_print_ar "${q_uuid}" "${q_pub}"
      else
        note "[AR] Skipping decode for ${q_uuid} (no verifier pubkey available)."
      fi
    done < "${AR_QUEUE_FILE}"
  fi

  # ========================================================================
  # Cleanup Notes
  # ========================================================================
  note "All parallel runs complete."
  info "Containers from the run(s) are left running for inspection."
  info "To clean up all attester/verifier pairs, simply re-run this script."
  info "To clean up the shared mock-s3, run: docker compose -f containers/compose.shared.yaml down"

  exit $final_exit_code
}

# Execute main function with all arguments
main "$@"
