#!/bin/bash
set -euo pipefail

# Purpose:
#   Run an optional integration test of the bridge against a real Vaultwarden
#   instance (docker compose). Exercises bearer auth + bw-cli secret fetch.
#
# Usage:
#   ./scripts/test-eso-bridge-integration.sh
#   ./scripts/test-eso-bridge-integration.sh --keep
#
# Prerequisites:
#   - docker with compose plugin
#   - python3/python with the cryptography package (only if generating certs on host;
#     the seed container installs cryptography itself)
#
# Notes:
#   - Unit tests remain the default CI path (./scripts/test-eso-bridge-unit.sh).
#   - This job is intentionally opt-in (local or workflow_dispatch).

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_FILE="${REPO_ROOT}/tests/integration/docker-compose.yml"
CERT_DIR="${REPO_ROOT}/tests/integration/.certs"
BRIDGE_HOST_PORT="${BRIDGE_HOST_PORT:-18081}"
KEEP=0

for arg in "$@"; do
  case "${arg}" in
    --keep) KEEP=1 ;;
    -h|--help)
      sed -n '2,20p' "$0"
      exit 0
      ;;
    *)
      echo "Unknown argument: ${arg}" >&2
      exit 2
      ;;
  esac
done

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker not found on PATH"
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "ERROR: docker compose plugin not available"
  exit 1
fi

if command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN="python"
else
  echo "ERROR: python3/python not found on PATH (needed to generate TLS certs)"
  exit 1
fi

cleanup() {
  if [[ "${KEEP}" -eq 1 ]]; then
    echo "Keeping compose stack (--keep)."
    return
  fi
  echo "Tearing down integration stack..."
  docker compose -f "${COMPOSE_FILE}" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> Generating self-signed TLS certs for Vaultwarden"
mkdir -p "${CERT_DIR}"
if ! "${PYTHON_BIN}" -c "import cryptography" >/dev/null 2>&1; then
  echo "Installing cryptography for cert generation..."
  "${PYTHON_BIN}" -m pip install --user -q cryptography
fi
"${PYTHON_BIN}" "${REPO_ROOT}/tests/integration/generate_certs.py" --out-dir "${CERT_DIR}"

export BRIDGE_HOST_PORT

echo "==> Starting Vaultwarden"
docker compose -f "${COMPOSE_FILE}" up -d vaultwarden

echo "==> Seeding Vaultwarden user + secret item"
docker compose -f "${COMPOSE_FILE}" run --rm --no-deps seed

echo "==> Building and starting bridge (bw-cli backend)"
docker compose -f "${COMPOSE_FILE}" up -d --build bridge

echo "==> Waiting for bridge /healthz"
deadline=$((SECONDS + 120))
until curl -fsS "http://127.0.0.1:${BRIDGE_HOST_PORT}/healthz" >/dev/null 2>&1; do
  if (( SECONDS >= deadline )); then
    echo "ERROR: bridge did not become healthy in time"
    docker compose -f "${COMPOSE_FILE}" logs bridge || true
    exit 1
  fi
  sleep 2
done

echo "==> Assert unauthorized without bearer token"
status="$(curl -sS -o /tmp/bridge-int-unauth.json -w '%{http_code}' \
  "http://127.0.0.1:${BRIDGE_HOST_PORT}/v1/secret/default/demo-secret/api-key")"
if [[ "${status}" != "401" ]]; then
  echo "ERROR: expected HTTP 401 without token, got ${status}"
  cat /tmp/bridge-int-unauth.json || true
  exit 1
fi

echo "==> Assert unauthorized with wrong bearer token"
status="$(curl -sS -o /tmp/bridge-int-wrong.json -w '%{http_code}' \
  -H 'Authorization: Bearer wrong-token' \
  "http://127.0.0.1:${BRIDGE_HOST_PORT}/v1/secret/default/demo-secret/api-key")"
if [[ "${status}" != "401" ]]; then
  echo "ERROR: expected HTTP 401 with wrong token, got ${status}"
  cat /tmp/bridge-int-wrong.json || true
  exit 1
fi

echo "==> Assert auth + secret fetch success via real Vaultwarden/bw-cli"
status="$(curl -sS -o /tmp/bridge-int-ok.json -w '%{http_code}' \
  -H 'Authorization: Bearer example-only-bridge-token' \
  "http://127.0.0.1:${BRIDGE_HOST_PORT}/v1/secret/default/demo-secret/api-key")"
if [[ "${status}" != "200" ]]; then
  echo "ERROR: expected HTTP 200 on secret fetch, got ${status}"
  cat /tmp/bridge-int-ok.json || true
  docker compose -f "${COMPOSE_FILE}" logs bridge || true
  exit 1
fi

expected='"value": "<example-only-seed-field-value>"'
if ! grep -q '<example-only-seed-field-value>' /tmp/bridge-int-ok.json; then
  echo "ERROR: secret payload missing expected value"
  cat /tmp/bridge-int-ok.json
  exit 1
fi

echo "Integration test passed (auth + Vaultwarden secret fetch)."
echo "Response: $(cat /tmp/bridge-int-ok.json)"
