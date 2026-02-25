#!/bin/bash
set -euo pipefail

# Purpose:
#   Package and publish the reusable Vaultwarden ESO bridge Helm chart to GHCR
#   as an OCI artifact for external consumption.
#
# Usage:
#   ./scripts/publish-secrets-platform-bridge-chart.sh [--version <semver>] [--dry-run]
#
# Prerequisites:
#   - helm v3 installed
#   - GHCR_USERNAME set (for example: github actor)
#   - GHCR_TOKEN set (PAT or GITHUB_TOKEN with packages:write)
#   - Optional GHCR_REPOSITORY override (default: josh-archer/secrets-platform-charts)

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHART_DIR="${REPO_ROOT}/grok-servaar/infra/secrets-platform/bridge/chart/vaultwarden-eso-bridge"
OUTPUT_DIR="${REPO_ROOT}/.artifacts/helm"
GHCR_REPOSITORY="${GHCR_REPOSITORY:-josh-archer/secrets-platform-charts}"

VERSION_OVERRIDE=""
DRY_RUN="false"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      VERSION_OVERRIDE="${2:-}"
      shift 2
      ;;
    --dry-run)
      DRY_RUN="true"
      shift
      ;;
    *)
      echo "ERROR: unknown argument: $1"
      exit 1
      ;;
  esac
done

if ! command -v helm >/dev/null 2>&1; then
  echo "ERROR: helm is required."
  exit 1
fi

CHART_VERSION="$(awk '/^version:[[:space:]]+/ {print $2; exit}' "${CHART_DIR}/Chart.yaml")"
if [[ -z "${CHART_VERSION}" ]]; then
  echo "ERROR: could not resolve chart version from Chart.yaml."
  exit 1
fi

PACKAGE_VERSION="${VERSION_OVERRIDE:-${CHART_VERSION}}"
if [[ ! "${PACKAGE_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([\-+][0-9A-Za-z\.-]+)?$ ]]; then
  echo "ERROR: version must be semver-compatible (got: ${PACKAGE_VERSION})."
  exit 1
fi

echo "Linting bridge chart..."
helm lint "${CHART_DIR}"

mkdir -p "${OUTPUT_DIR}"
echo "Packaging bridge chart version ${PACKAGE_VERSION}..."
PACKAGE_FILE="$(
  helm package "${CHART_DIR}" \
    --version "${PACKAGE_VERSION}" \
    --destination "${OUTPUT_DIR}" \
  | awk '/Successfully packaged chart and saved it to:/ {print $NF}'
)"

if [[ -z "${PACKAGE_FILE}" || ! -f "${PACKAGE_FILE}" ]]; then
  echo "ERROR: chart package output was not created."
  exit 1
fi

echo "Packaged chart: ${PACKAGE_FILE}"

if [[ "${DRY_RUN}" == "true" ]]; then
  echo "Dry run enabled; skipping GHCR login/push."
  exit 0
fi

if [[ -z "${GHCR_USERNAME:-}" || -z "${GHCR_TOKEN:-}" ]]; then
  echo "ERROR: GHCR_USERNAME and GHCR_TOKEN must be set when not using --dry-run."
  exit 1
fi

echo "Logging in to GHCR..."
echo "${GHCR_TOKEN}" | helm registry login ghcr.io -u "${GHCR_USERNAME}" --password-stdin

echo "Pushing chart to oci://ghcr.io/${GHCR_REPOSITORY}..."
helm push "${PACKAGE_FILE}" "oci://ghcr.io/${GHCR_REPOSITORY}"

echo "Bridge chart publish complete."
