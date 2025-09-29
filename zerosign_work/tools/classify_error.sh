#!/usr/bin/env bash
#
# classify_error.sh: Verifies an HMAC error tag and looks up its meaning.
#
set -euo pipefail

err() { printf "\e[31m[ERR]\e[0m %s\n" "$*" >&2; }
note(){ printf "\e[35m[ORCH]\e[0m %s\n" "$*"; }

if [[ -z "${1:-}" ]];
then
  err "Usage: $0 <eca_uuid>"
  exit 1
fi

ECA_UUID="$1"
# FIX: Go up one more directory to get the true project root
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Dynamically generate the list from the canonical source
ERROR_CODES_STR=$(gawk '/:/ {print $1}' "${PROJECT_ROOT}/errors/registry.yml" | tr -d ':' | tr '\n' ' ')
ERROR_CODES=($ERROR_CODES_STR)

# Use a temporary container to access volumes and run lib helpers
docker run --rm --name "err-classifier-${ECA_UUID:0:8}" \
  -e ECA_UUID="$ECA_UUID" \
  -v "zsn_verifier_secrets:/secrets:ro" \
  -v "zsn_attestation_results:/results:ro" \
  -v "${PROJECT_ROOT}:/app:ro" \
  python:3.11-slim bash -lc '
set -euo pipefail

# FIX: Install jq, as it is not in the base image
apt-get update >/dev/null && apt-get install -y jq >/dev/null

# Read the necessary secrets and the error tag
BF_B64URL=$(cat "/secrets/verifier/'"${ECA_UUID}"'/bf.b64url")
TAG_HEX=$(cat "/results/'"${ECA_UUID}"'/results.status")
MATCHED_CODE=""

# Loop through known error codes and verify the HMAC tag
for CODE in '"${ERROR_CODES[*]}"'; do
  VERDICT=$(python /app/zerosign-work/lib/results_status_verify.py <<< \
    "{\"bf_b64url\": \"${BF_B64URL}\", \"eca_uuid\": \"${ECA_UUID}\", \"hmac_hex\": \"${TAG_HEX}\", \"error_code\": \"${CODE}\"}")

  if [[ $(jq -r .valid <<< "$VERDICT") == "true" ]]; then
    MATCHED_CODE=$CODE
    break
  fi
done

if [[ -z "$MATCHED_CODE" ]]; then
  echo "[ORCH] Unknown results.status tag (no registry match)." >&2
  echo "HMAC tag: ${TAG_HEX}" >&2
  exit 1
fi

# Look up the description for the matched code
DESC=$(python /app/zerosign-work/lib/error_registry_lookup.py <<< \
  "{\"code\": \"${MATCHED_CODE}\"}")

REASON=$(jq -r .description <<< "$DESC")
note "Classified verifier error: ${MATCHED_CODE} — ${REASON}"
'
