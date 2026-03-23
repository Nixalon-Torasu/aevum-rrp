#!/usr/bin/env bash
set -euo pipefail

# GitOps installer: policy-only convergence.
# MUST NOT touch tool surfaces (/usr/local, /opt, /etc/systemd, bootkit trust root).

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

FORBIDDEN_TOP=("bin" "usr" "opt" "systemd" "pack" "bootkit" "bootstrap")
for d in "${FORBIDDEN_TOP[@]}"; do
  if [[ -e "${ROOT}/${d}" ]]; then
    echo "ERROR: gitops artifact contains forbidden top-level '${d}'. Refusing." >&2
    exit 2
  fi
done

# Allowed sources
SRC_REG="${ROOT}/etc/aevum/registry"
SRC_BUNDLES="${ROOT}/etc/aevum/bundles.d"
SRC_EGRESS="${ROOT}/etc/aevum/egress_profiles.d"

# Allowed destinations
DST_BASE="/etc/aevum"
DST_REG="${DST_BASE}/registry"
DST_BUNDLES="${DST_BASE}/bundles.d"
DST_EGRESS="${DST_BASE}/egress_profiles.d"

install -d -m 0755 "$DST_BASE"

sync_dir() {
  local src="$1" dst="$2"
  if [[ ! -d "$src" ]]; then
    return 0
  fi
  install -d -m 0755 "$dst"
  rsync -a --delete "${src}/" "${dst}/"
}

echo "[gitops] syncing policy dirs..."
sync_dir "$SRC_REG" "$DST_REG"
sync_dir "$SRC_BUNDLES" "$DST_BUNDLES"
sync_dir "$SRC_EGRESS" "$DST_EGRESS"

echo "[gitops] done."
