
#!/usr/bin/env bash
set -euo pipefail

# AEVUM EXTERNAL BOOT SETUP (v0_8)
# This kit is intentionally small: it establishes the operator “airlock”
# conventions and installs the update/apply entrypoints.
#
# NOTE: If you are installing Aevum on an internal OS drive, you may NOT need to
# run this script. You can still apply the bootkit via the bundle pipeline.

MODE="${AEVUM_MODE:-install}"

echo "== AEVUM EXTERNAL BOOT SETUP v0_8 =="
echo "mode=$MODE"
echo

# Best-effort baseline packages (non-fatal if networking is locked)
if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update -y || true
  sudo apt-get install -y unzip jq git rsync python3 python3-venv nftables tpm2-tools || true
fi

# Install bootkit entrypoints
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
sudo "$SCRIPT_DIR/bootkit/install_bootkit.sh" --mode "$MODE"

echo
echo "Next steps (typical):"
echo "  1) Copy 3 zips into /srv/aevum-hot/transfer/airlock/"
echo "  2) sudo aevum-bootstrap-update"
echo "  3) sudo aevum-bootstrap-apply"
echo
echo "Docs:"
echo "  bootkit/OPERATOR_DOCTRINE.md"
echo "  bootkit/BUNDLE_CONTRACT.md"
