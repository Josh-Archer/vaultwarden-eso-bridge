#!/bin/bash
set -euo pipefail

# Purpose:
#   Run unit/contract tests for the Vaultwarden ESO bridge module.
#
# Usage:
#   ./scripts/test-eso-bridge-unit.sh
#
# Prerequisites:
#   - python3 available on PATH

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

echo "Running bridge unit tests..."
python3 -m unittest discover -s grok-servaar/infra/secrets-platform/bridge/tests -p "test_*.py"
echo "Bridge unit tests passed."
