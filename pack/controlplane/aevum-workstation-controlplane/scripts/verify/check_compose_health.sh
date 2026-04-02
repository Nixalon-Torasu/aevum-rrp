#!/usr/bin/env bash
set -euo pipefail

echo "VERIFY: compose containers health (best-effort)"
if ! command -v docker >/dev/null 2>&1; then
  echo "SKIP: docker not installed"
  exit 0
fi

docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}' || true
# Optional: fail on restart loops
if docker ps --format '{{.Names}} {{.Status}}' | grep -E 'Restarting|Exited' >/dev/null 2>&1; then
  echo "WARN: some containers not healthy/running"
  exit 1
fi
echo "OK: no obvious restart loops"
