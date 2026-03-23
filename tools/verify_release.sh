#!/usr/bin/env bash
set -euo pipefail

ZIP="${1:-}"
SIG="${2:-}"
if [[ -z "${ZIP}" || -z "${SIG}" ]]; then
  echo "Usage: $0 dist/<pack>.zip dist/<pack>.zip.asc"
  exit 2
fi

gpg --verify "${SIG}" "${ZIP}"
echo "OK: signature valid"
