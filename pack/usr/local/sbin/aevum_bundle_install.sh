#!/usr/bin/env bash
set -euo pipefail

# aevum-bundle-install
# Deterministic-ish "bundle" installer for Ubuntu 24.04 server minimal.
#
# Principles:
# - Bundles are additive. They configure hardware/runtime essentials and record evidence.
# - Bundles do NOT gate Aevum runtime daemons. They are operator actions.
# - All installs should run inside bounded egress (use profile "apt").
#
# Bundle definitions live in: /etc/aevum/bundles.d/<name>.conf
# Format (shell):
#   BUNDLE_NAME="..."
#   APT_PACKAGES=(... ...)
#   POST_COMMANDS=( "cmd1" "cmd2" ... )   # optional
#
# Evidence:
# - Writes a manifest to /var/lib/aevum/workstation/bundles/<name>/<ts>.json
# - Emits an Aevum receipt (chain I) with sha256(manifest)

NAME="${1:-}"
[[ -n "${NAME}" ]] || { echo "Usage: aevum-bundle-install <bundle-name>"; exit 2; }

CONF="/etc/aevum/bundles.d/${NAME}.conf"
[[ -f "${CONF}" ]] || { echo "Missing bundle: ${CONF}"; exit 2; }

# shellcheck disable=SC1090
source "${CONF}"

: "${BUNDLE_NAME:=${NAME}}"

# Export variables used by the manifest generator
export NAME
export BUNDLE_NAME
# Export package list as a stable, space-separated string
APT_PACKAGES_STR="$(printf "%s " "${APT_PACKAGES[@]:-}")"
export APT_PACKAGES_STR

BASE="${BASE:-/var/lib/aevum/workstation}"
OUTDIR="${BASE}/bundles/${NAME}"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${OUTDIR}/manifest_${TS}.json"
mkdir -p "${OUTDIR}"

# Ensure apt profile exists (best-effort)
EGRESS_RUN="/opt/aevum-tools/bin/aevum-firewallctl"
RUNNER="/opt/aevum-tools/bin/aevum-egress-profile-run"
APT_CMD="apt-get install -y ${APT_PACKAGES[*]}"

echo "== Aevum bundle: ${BUNDLE_NAME} =="
echo "packages: ${#APT_PACKAGES[@]}"

# Run apt install within bounded egress window if possible.
APT_RC=0
if [[ -x "${RUNNER}" ]]; then
  # 45 min window default for big installs
  set +e
  "${RUNNER}" apt 2700 -- bash -lc "apt-get update && ${APT_CMD}"
  APT_RC=$?
  set -e
else
  set +e
  apt-get update
  ${APT_CMD}
  APT_RC=$?
  set -e
fi
export APT_RC

if [[ "${APT_RC}" -ne 0 ]]; then
  echo "FAIL: apt install returned rc=${APT_RC} (manifest will still be written)" >&2
fi

# Post commands (best-effort; skipped if apt failed)
if [[ "${APT_RC}" -eq 0 ]] && declare -p POST_COMMANDS >/dev/null 2>&1; then
  for cmd in "${POST_COMMANDS[@]}"; do
    bash -lc "${cmd}" || true
  done
fi

# Manifest (dpkg status is the truth)
python3 - <<'PY' > "${OUT}"
import json,os,subprocess,datetime,platform,hashlib
name=os.environ.get("NAME","")
bname=os.environ.get("BUNDLE_NAME","")
pkgs=os.environ.get("APT_PACKAGES_STR","").split()
apt_rc=int(os.environ.get("APT_RC","0") or "0")
def run(cmd):
    try:
        return subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    except Exception:
        return ""
dpkg = run(["dpkg-query","-W","-f","${Package}\t${Version}\t${Architecture}\n"])
installed={}
for ln in dpkg.splitlines():
    parts=ln.split("\t")
    if len(parts)>=2:
        installed[parts[0]]= {"version":parts[1], "arch": parts[2] if len(parts)>2 else ""}
sel={}
for p in pkgs:
    if p in installed:
        sel[p]=installed[p]
meta={
  "bundle": name,
  "bundle_name": bname,
  "timestamp_utc": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
  "hostname": platform.node(),
  "packages_requested": pkgs,
  "packages_installed_subset": sel,
  "apt_returncode": apt_rc,
}
print(json.dumps(meta, indent=2, sort_keys=True))
PY

sha="$(sha256sum "${OUT}" | awk '{print $1}')"

if [[ -x /opt/aevum-tools/bin/aevum-receipt ]]; then
  if [[ "${APT_RC}" -eq 0 ]]; then
    /opt/aevum-tools/bin/aevum-receipt note "bundle installed" component=bundle bundle="${NAME}" manifest="sha256:${sha}" || true
  else
    /opt/aevum-tools/bin/aevum-receipt warn "bundle install had errors" component=bundle bundle="${NAME}" apt_rc="${APT_RC}" manifest="sha256:${sha}" || true
  fi
fi

echo "OK: ${OUT} sha256:${sha}"

# If apt failed, propagate the failure after evidence is written
if [[ "${APT_RC}" -ne 0 ]]; then
  exit "${APT_RC}"
fi
