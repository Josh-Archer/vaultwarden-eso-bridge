#!/bin/bash
set -euo pipefail

# Purpose:
#   Run unit/contract tests for the Vaultwarden ESO bridge module.
#
# Usage:
#   ./scripts/test-eso-bridge-unit.sh
#
# Prerequisites:
#   - python3 or python available on PATH

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

echo "Running bridge unit tests..."
"${PYTHON_BIN}" -m unittest discover -s tests -p "test_*.py"
echo "Bridge unit tests passed."
