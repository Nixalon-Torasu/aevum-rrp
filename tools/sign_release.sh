#!/usr/bin/env bash
set -euo pipefail

ZIP="${1:-}"
if [[ -z "${ZIP}" || ! -f "${ZIP}" ]]; then
  echo "Usage: $0 dist/<pack>.zip"
  exit 2
fi

if ! command -v gpg >/dev/null 2>&1; then
  echo "ERROR: gpg not installed"
  exit 3
fi

# Uses your default secret key (configure with gpg --list-secret-keys)
gpg --batch --yes --armor --detach-sign "${ZIP}"
echo "OK: wrote ${ZIP}.asc"
