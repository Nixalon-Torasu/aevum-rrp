#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bash "$DIR/check_no_wan_ports.sh"
bash "$DIR/check_compose_health.sh" || true
bash "$DIR/hash_state.sh"
echo "VERIFY: done"
