
#!/usr/bin/env bash
set -euo pipefail

MODE="install"
if [ "${1:-}" = "--mode" ]; then
  MODE="${2:-install}"
fi

echo "== AEVUM BOOTKIT INSTALL =="
echo "mode=$MODE"

# Airlock folders (operator drop zone)
sudo install -d -m 0755 /srv/aevum-hot/transfer 2>/dev/null || true
sudo install -d -m 0755 /srv/aevum-hot/transfer/airlock 2>/dev/null || true
sudo install -d -m 0755 /srv/aevum-hot/transfer/bootstrap 2>/dev/null || true

# Install operator entrypoints
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../bootkit/bin" && pwd)"
sudo install -m 0755 "$SRC_DIR/aevum-bootstrap-update" /usr/local/sbin/aevum-bootstrap-update
sudo install -m 0755 "$SRC_DIR/aevum-bootstrap-apply"  /usr/local/sbin/aevum-bootstrap-apply
sudo install -m 0755 "$SRC_DIR/aevum-modectl"          /usr/local/sbin/aevum-modectl
sudo install -m 0755 "$SRC_DIR/aevum-receipt-wipe"      /usr/local/sbin/aevum-receipt-wipe
sudo install -m 0755 "$SRC_DIR/aevum-release-key-rotate" /usr/local/sbin/aevum-release-key-rotate


# Default mode if not set
if [ ! -f /etc/aevum/mode ]; then
  echo "$MODE" | sudo tee /etc/aevum/mode >/dev/null
  sudo chmod 0644 /etc/aevum/mode || true

# Seed trust root (release pubkey) if absent
sudo install -d -m 0755 /etc/aevum/trust 2>/dev/null || true
if [ ! -f /etc/aevum/trust/release_pubkey.ed25519.b64 ]; then
  sudo install -m 0644 "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/etc/aevum/trust/release_pubkey.ed25519.b64" /etc/aevum/trust/release_pubkey.ed25519.b64
fi
if [ ! -f /etc/aevum/trust/trust_epoch.json ]; then
  sudo install -m 0644 "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/etc/aevum/trust/trust_epoch.json" /etc/aevum/trust/trust_epoch.json
fi

fi

echo "Installed:"
echo "  /usr/local/sbin/aevum-bootstrap-update"
echo "  /usr/local/sbin/aevum-bootstrap-apply"
echo "  /usr/local/sbin/aevum-modectl"
echo
echo "Airlock:"
echo "  /srv/aevum-hot/transfer/airlock"
echo
echo "== DONE =="
