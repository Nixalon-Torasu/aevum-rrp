#!/usr/bin/env bash
set -euo pipefail

# GitOps update runner for /opt/aevum-controlplane.
# Secure flow:
# - fetch tags
# - checkout a target tag (pinned or latest by pattern)
# - require signed tag + (optionally) signed commit
# - apply

CP_DIR="/opt/aevum-controlplane"
CONTROL_CONF="/etc/aevum/controlplane.conf"
KEYSDIR="/etc/aevum/trustedkeys.d"
CONTROLPLANE_TRUSTEDKEYS_DIR="${CONTROLPLANE_TRUSTEDKEYS_DIR:-${KEYSDIR}}"
KEYSDIR="${CONTROLPLANE_TRUSTEDKEYS_DIR}"

[[ -d "${CP_DIR}" ]] || exit 0
cd "${CP_DIR}"

# Defaults (overridable by /etc/aevum/controlplane.conf)
CONTROLPLANE_REQUIRE_SIGNED_TAG="${CONTROLPLANE_REQUIRE_SIGNED_TAG:-1}"
CONTROLPLANE_REQUIRE_SIGNED_COMMIT="${CONTROLPLANE_REQUIRE_SIGNED_COMMIT:-1}"
CONTROLPLANE_REQUIRE_CLEAN_TREE="${CONTROLPLANE_REQUIRE_CLEAN_TREE:-1}"
CONTROLPLANE_TARGET_TAG="${CONTROLPLANE_TARGET_TAG:-}"
CONTROLPLANE_TAG_PATTERN="${CONTROLPLANE_TAG_PATTERN:-v*}"
CONTROLPLANE_GNUPGHOME="${CONTROLPLANE_GNUPGHOME:-/etc/aevum/gnupg}"

if [[ -f "${CONTROL_CONF}" ]]; then
  # shellcheck disable=SC1090
  source "${CONTROL_CONF}"
fi

export GIT_TERMINAL_PROMPT=0
export GNUPGHOME="${CONTROLPLANE_GNUPGHOME}"

prep_gpg_allowlist() {
  local need="0"
  [[ "${CONTROLPLANE_REQUIRE_SIGNED_TAG}" == "1" ]] && need="1"
  [[ "${CONTROLPLANE_REQUIRE_SIGNED_COMMIT}" == "1" ]] && need="1"
  [[ "${need}" == "1" ]] || return 0

  command -v gpg >/dev/null 2>&1 || {
    [[ -x /opt/aevum-tools/bin/aevum-receipt ]] && /opt/aevum-tools/bin/aevum-receipt note "controlplane update refused (gpg missing)" component=controlplane || true
    if [[ -z "${CONTROLPLANE_TARGET_TAG}" ]]; then
      [[ -x /opt/aevum-tools/bin/aevum-receipt ]] && /opt/aevum-tools/bin/aevum-receipt note "controlplane update skipped (gpg missing)" component=controlplane || true
      echo "SKIP: gpg missing; not applying updates."
      exit 0
    fi
    echo "REFUSE: gpg missing (install: apt-get install gnupg)" >&2
    exit 2
  }

  mkdir -p "${GNUPGHOME}" "${KEYSDIR}"
  chmod 0700 "${GNUPGHOME}" || true
  chmod 0755 "${KEYSDIR}" || true

  shopt -s nullglob
  local keys=("${KEYSDIR}"/*.asc "${KEYSDIR}"/*.pgp "${KEYSDIR}"/*.gpg)
  if (( ${#keys[@]} == 0 )); then
    [[ -x /opt/aevum-tools/bin/aevum-receipt ]] && /opt/aevum-tools/bin/aevum-receipt note "controlplane update refused (no trusted keys)" component=controlplane keysdir="${KEYSDIR}" || true
    if [[ -z "${CONTROLPLANE_TARGET_TAG}" ]]; then
      [[ -x /opt/aevum-tools/bin/aevum-receipt ]] && /opt/aevum-tools/bin/aevum-receipt note "controlplane update skipped (no trusted keys)" component=controlplane keysdir="${KEYSDIR}" || true
      echo "SKIP: no trusted signer keys; not applying updates."
      exit 0
    fi
    echo "REFUSE: no trusted signer pubkeys in ${KEYSDIR} (add *.asc; then run: aevum-gpgctl import-dir)" >&2
    exit 2
  fi

  gpg --homedir "${GNUPGHOME}" --batch --quiet --import "${keys[@]}" >/dev/null 2>&1 || true
}

# Pull/fetch (only if origin exists)
HAS_ORIGIN=0
if git remote get-url origin >/dev/null 2>&1; then
  HAS_ORIGIN=1
  git fetch --tags --prune origin || true
fi

# Clean tree gate (optional)
if [[ "${CONTROLPLANE_REQUIRE_CLEAN_TREE}" == "1" ]]; then
  if ! git diff --quiet >/dev/null 2>&1; then
    [[ -x /opt/aevum-tools/bin/aevum-receipt ]] && /opt/aevum-tools/bin/aevum-receipt note "controlplane update refused (dirty tree)" component=controlplane || true
    echo "REFUSE: dirty working tree in ${CP_DIR}" >&2
    exit 5
  fi
fi

# Signed-tag gate (optional, but recommended)
if [[ "${CONTROLPLANE_REQUIRE_SIGNED_TAG}" == "1" ]]; then
  # If this is still a local-only seed (no origin) and no tags, idle instead of failing.
  if [[ "${HAS_ORIGIN}" == "0" && -z "${CONTROLPLANE_TARGET_TAG}" ]]; then
    maybe_tag="$(git tag --list "${CONTROLPLANE_TAG_PATTERN}" --sort=-v:refname | head -n 1 || true)"
    [[ -z "${maybe_tag}" ]] && exit 0
  fi

  prep_gpg_allowlist

  tag="${CONTROLPLANE_TARGET_TAG}"
  if [[ -z "${tag}" ]]; then
    tag="$(git tag --list "${CONTROLPLANE_TAG_PATTERN}" --sort=-v:refname | head -n 1 || true)"
  fi
  if [[ -z "${tag}" ]]; then
    [[ -x /opt/aevum-tools/bin/aevum-receipt ]] && /opt/aevum-tools/bin/aevum-receipt note "controlplane update refused (no tags)" component=controlplane pattern="${CONTROLPLANE_TAG_PATTERN}" || true
    echo "REFUSE: no tags found matching ${CONTROLPLANE_TAG_PATTERN}" >&2
    exit 3
  fi

  if ! git tag -v "${tag}" >/dev/null 2>&1; then
    [[ -x /opt/aevum-tools/bin/aevum-receipt ]] && /opt/aevum-tools/bin/aevum-receipt note "controlplane update refused (bad tag sig)" component=controlplane tag="${tag}" || true
    echo "REFUSE: tag signature invalid: ${tag}" >&2
    exit 4
  fi

  git checkout -f "${tag}" >/dev/null 2>&1 || git checkout -f "tags/${tag}" >/dev/null 2>&1
fi

# Signed-commit gate (optional)
if [[ "${CONTROLPLANE_REQUIRE_SIGNED_COMMIT}" == "1" ]]; then
  prep_gpg_allowlist
  if ! git verify-commit HEAD >/dev/null 2>&1; then
    [[ -x /opt/aevum-tools/bin/aevum-receipt ]] && /opt/aevum-tools/bin/aevum-receipt note "controlplane update refused (bad commit sig)" component=controlplane || true
    echo "REFUSE: commit signature invalid: HEAD" >&2
    exit 6
  fi
fi

# Apply via ansible if venv exists
APPLY_RC=0
if [[ -x "${CP_DIR}/.venv/bin/ansible-playbook" ]]; then
  # shellcheck disable=SC1091
  source "${CP_DIR}/.venv/bin/activate" || true
  set +e
  make apply
  APPLY_RC=$?
  set -e
else
  echo "NOTE: controlplane venv missing; run: ${CP_DIR}/scripts/bootstrap_local.sh" >&2
  if [[ -n "${CONTROLPLANE_TARGET_TAG:-}" ]]; then
    [[ -x /opt/aevum-tools/bin/aevum-receipt ]] && /opt/aevum-tools/bin/aevum-receipt note "controlplane update refused (venv missing)" component=controlplane tag="${CONTROLPLANE_TARGET_TAG}" dir="${CP_DIR}" || true
    echo "REFUSE: venv missing; cannot apply forced tag ${CONTROLPLANE_TARGET_TAG}." >&2
    exit 2
  fi
  [[ -x /opt/aevum-tools/bin/aevum-receipt ]] && /opt/aevum-tools/bin/aevum-receipt note "controlplane update skipped (venv missing)" component=controlplane dir="${CP_DIR}" || true
  echo "SKIP: venv missing; not applying." >&2
  exit 0
fi

if [[ "${APPLY_RC}" -ne 0 ]]; then
  [[ -x /opt/aevum-tools/bin/aevum-receipt ]] && /opt/aevum-tools/bin/aevum-receipt warn "controlplane apply failed" component=controlplane rc="${APPLY_RC}" dir="${CP_DIR}" || true
  echo "FAIL: controlplane apply failed (rc=${APPLY_RC})" >&2
  exit "${APPLY_RC}"
fi

# Reseal registry manifest after controlplane apply (device-bound)

# Receipt an operator note (gating on successful apply)
if [[ -x /opt/aevum-tools/bin/aevum-receipt ]]; then
  /opt/aevum-tools/bin/aevum-receipt note "controlplane update+apply ok" component=controlplane dir="${CP_DIR}" || true
fi

/opt/aevum-tools/bin/aevum-registry-seal --base /var/lib/aevum/workstation --registry /etc/aevum/registry --tpm || true
