#!/usr/bin/env bash
set -euo pipefail

CP_DIR="/opt/aevum-controlplane"

[[ -d "$CP_DIR" ]] || exit 0
cd "$CP_DIR"

# Best-effort pull (only if origin exists)
if git remote get-url origin >/dev/null 2>&1; then
  git fetch --all --prune || true
  git pull --ff-only || true
fi

# Apply via ansible if venv exists
if [[ -x "$CP_DIR/.venv/bin/ansible-playbook" ]]; then
  source "$CP_DIR/.venv/bin/activate"
  make apply || true
else
  echo "NOTE: controlplane venv missing; run: $CP_DIR/scripts/bootstrap_local.sh" >&2
fi

# Receipt an operator note (non-gating)
if command -v aevum_receiptctl.py >/dev/null 2>&1; then
  aevum_receiptctl.py --base /var/lib/aevum/workstation --kind note --message "controlplane update+apply ran" component=controlplane dir="$CP_DIR" || true
fi

# Reseal registry manifest after controlplane apply (device-bound)
/opt/aevum-tools/bin/aevum-registry-seal --base /var/lib/aevum/workstation --registry /etc/aevum/registry --tpm || true
