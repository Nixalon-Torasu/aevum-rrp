#!/usr/bin/env bash
set -euo pipefail

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/compose"
DEST="/opt/ai-stack"

sudo mkdir -p "$DEST"
sudo rsync -a --delete "$SRC_DIR"/ "$DEST"/

echo "Installed compose layout to $DEST"
echo "Next:"
echo "  sudo -H bash -lc 'cd /opt/ai-stack/observability && docker compose up -d'"
