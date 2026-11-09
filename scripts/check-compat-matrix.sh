#!/bin/bash
set -euo pipefail

# Purpose:
#   Verify the ESO / bw CLI compatibility matrix.
#   Confirms docs/compatibility.md matches compat/matrix.json, that every
#   listed version exists, and (unless --no-exercise) that each bw CLI
#   exposes the commands the bridge calls. Does not log in or write secrets.
#
# Usage:
#   ./scripts/check-compat-matrix.sh
#   ./scripts/check-compat-matrix.sh --no-exercise
#   ./scripts/check-compat-matrix.sh --write
#   ./scripts/check-compat-matrix.sh --skip-remote

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

if command -v python3 >/dev/null 2>&1; then
  PYTHON_BIN="python3"
elif command -v python >/dev/null 2>&1; then
  PYTHON_BIN="python"
else
  echo "ERROR: python3/python not found on PATH"
  exit 1
fi

exercise=1
args=()
for arg in "$@"; do
  if [[ "${arg}" == "--no-exercise" ]]; then
    exercise=0
  else
    args+=("${arg}")
  fi
done
if [[ "${exercise}" -eq 1 ]]; then
  args+=("--exercise-cli")
fi

echo "Checking ESO and bw CLI compatibility matrix..."
"${PYTHON_BIN}" scripts/compat_matrix.py "${args[@]}"
echo "Compatibility matrix check passed."
