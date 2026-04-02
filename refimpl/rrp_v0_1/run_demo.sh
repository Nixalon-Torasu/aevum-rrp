#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Aevum RRP v0.1.1 Demo ==="
echo
bash "$ROOT_DIR/tests/test_tamper.sh"
