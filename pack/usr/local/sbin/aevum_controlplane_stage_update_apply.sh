#!/usr/bin/env bash
set -euo pipefail

# GitOps update runner for /opt/aevum-controlplane (staged apply).
# Flow:
# 1) Fetch tags
# 2) Select target tag (pinned or latest by pattern)
# 3) Verify signed tag + signed commit (if required)
# 4) Create a temporary git worktree at that tag
# 5) Apply from the staged worktree (so current working tree stays stable during apply)
# 6) Only after apply succeeds, fast-checkout CP_DIR to the same tag

CP_DIR="/opt/aevum-controlplane"
CONTROL_CONF="/etc/aevum/controlplane.conf"
KEYSDIR="/etc/aevum/trustedkeys.d"
CONTROLPLANE_TRUSTEDKEYS_DIR="${CONTROLPLANE_TRUSTEDKEYS_DIR:-${KEYSDIR}}"
KEYSDIR="${CONTROLPLANE_TRUSTEDKEYS_DIR}"

[[ -d "${CP_DIR}" ]] || exit 0
cd "${CP_DIR}"

# Defaults (overridable)
CONTROLPLANE_REQUIRE_SIGNED_TAG="${CONTROLPLANE_REQUIRE_SIGNED_TAG:-1}"
CONTROLPLANE_REQUIRE_SIGNED_COMMIT="${CONTROLPLANE_REQUIRE_SIGNED_COMMIT:-1}"
CONTROLPLANE_REQUIRE_CLEAN_TREE="${CONTROLPLANE_REQUIRE_CLEAN_TREE:-1}"
CONTROLPLANE_TARGET_TAG="${CONTROLPLANE_TARGET_TAG:-}"
CONTROLPLANE_TAG_PATTERN="${CONTROLPLANE_TAG_PATTERN:-v*}"
CONTROLPLANE_GNUPGHOME="${CONTROLPLANE_GNUPGHOME:-/etc/aevum/gnupg}"
CONTROLPLANE_STAGE_DIR="${CONTROLPLANE_STAGE_DIR:-/opt/.aevum-controlplane.stage}"
CONTROLPLANE_ANSIBLE_CHECK_FIRST="${CONTROLPLANE_ANSIBLE_CHECK_FIRST:-0}"

if [[ -f "${CONTROL_CONF}" ]]; then
  # shellcheck disable=SC1090
  source "${CONTROL_CONF}"
fi

export GIT_TERMINAL_PROMPT=0
export GNUPGHOME="${CONTROLPLANE_GNUPGHOME}"

receipt_note() {
  if [[ -x /opt/aevum-tools/bin/aevum-receipt ]]; then
    /opt/aevum-tools/bin/aevum-receipt note "$@" component=controlplane || true
  fi
}

prep_gpg_allowlist() {
  local need="0"
  [[ "${CONTROLPLANE_REQUIRE_SIGNED_TAG}" == "1" ]] && need="1"
  [[ "${CONTROLPLANE_REQUIRE_SIGNED_COMMIT}" == "1" ]] && need="1"
  [[ "${need}" == "1" ]] || return 0

  command -v gpg >/dev/null 2>&1 || {
    if [[ -z "${CONTROLPLANE_TARGET_TAG}" ]]; then
      receipt_note "controlplane update skipped (gpg missing)"
      echo "SKIP: gpg missing; not applying updates."
      exit 0
    fi
    receipt_note "controlplane update refused (gpg missing)"
    echo "REFUSE: gpg missing (install: apt-get install gnupg)" >&2
    exit 2
  }

  mkdir -p "${GNUPGHOME}" "${KEYSDIR}"
  chmod 0700 "${GNUPGHOME}" || true
  chmod 0755 "${KEYSDIR}" || true

  shopt -s nullglob
  local keys=("${KEYSDIR}"/*.asc "${KEYSDIR}"/*.pgp "${KEYSDIR}"/*.gpg)
  if (( ${#keys[@]} == 0 )); then
    if [[ -z "${CONTROLPLANE_TARGET_TAG}" ]]; then
      receipt_note "controlplane update skipped (no trusted keys)" keysdir="${KEYSDIR}"
      echo "SKIP: no trusted signer keys; not applying updates."
      exit 0
    fi
    receipt_note "controlplane update refused (no trusted keys)" keysdir="${KEYSDIR}"
    echo "REFUSE: no trusted signer pubkeys in ${KEYSDIR} (add *.asc; then run: aevum-gpgctl import-dir)" >&2
    exit 2
  fi

  gpg --homedir "${GNUPGHOME}" --batch --quiet --import "${keys[@]}" >/dev/null 2>&1 || true
}

# Fetch tags if origin exists
HAS_ORIGIN=0
if git remote get-url origin >/dev/null 2>&1; then
  HAS_ORIGIN=1
  git fetch --tags --prune origin || true
fi

if [[ "${CONTROLPLANE_REQUIRE_CLEAN_TREE}" == "1" ]]; then
  if ! git diff --quiet >/dev/null 2>&1; then
    receipt_note "controlplane update refused (dirty tree)"
    echo "REFUSE: dirty working tree in ${CP_DIR}" >&2
    exit 5
  fi
fi

tag="${CONTROLPLANE_TARGET_TAG}"
if [[ -z "${tag}" ]]; then
  tag="$(git tag --list "${CONTROLPLANE_TAG_PATTERN}" --sort=-v:refname | head -n 1 || true)"
fi
if [[ -z "${tag}" ]]; then
  [[ "${HAS_ORIGIN}" == "0" ]] && exit 0
  receipt_note "controlplane update refused (no tags)" pattern="${CONTROLPLANE_TAG_PATTERN}"
  echo "REFUSE: no tags found matching ${CONTROLPLANE_TAG_PATTERN}" >&2
  exit 3
fi

if [[ "${CONTROLPLANE_REQUIRE_SIGNED_TAG}" == "1" ]]; then
  prep_gpg_allowlist
  if ! git tag -v "${tag}" >/dev/null 2>&1; then
    receipt_note "controlplane update refused (bad tag sig)" tag="${tag}"
    echo "REFUSE: tag signature invalid: ${tag}" >&2
    exit 4
  fi
fi

# Create staged worktree
rm -rf "${CONTROLPLANE_STAGE_DIR}" || true
mkdir -p "$(dirname "${CONTROLPLANE_STAGE_DIR}")" || true

git worktree add -f "${CONTROLPLANE_STAGE_DIR}" "${tag}" >/dev/null 2>&1 || {
  receipt_note "controlplane update refused (worktree add failed)" tag="${tag}"
  echo "REFUSE: cannot create staged worktree at tag ${tag}" >&2
  exit 7
}

cleanup() {
  git worktree remove -f "${CONTROLPLANE_STAGE_DIR}" >/dev/null 2>&1 || true
  rm -rf "${CONTROLPLANE_STAGE_DIR}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Signed commit gate (verify staged HEAD)
if [[ "${CONTROLPLANE_REQUIRE_SIGNED_COMMIT}" == "1" ]]; then
  prep_gpg_allowlist
  if ! git -C "${CONTROLPLANE_STAGE_DIR}" verify-commit HEAD >/dev/null 2>&1; then
    receipt_note "controlplane update refused (bad commit sig)" tag="${tag}"
    echo "REFUSE: commit signature invalid: ${tag}" >&2
    exit 6
  fi
fi

# Apply from staged dir using venv if present (best)
if [[ -x "${CP_DIR}/.venv/bin/ansible-playbook" ]]; then
  # shellcheck disable=SC1091
  source "${CP_DIR}/.venv/bin/activate" || true

  if [[ "${CONTROLPLANE_ANSIBLE_CHECK_FIRST}" == "1" ]]; then
    ( cd "${CONTROLPLANE_STAGE_DIR}" && ansible-playbook -i inventory/localhost.yml playbooks/site.yml --check ) || {
      receipt_note "controlplane update refused (ansible --check failed)" tag="${tag}"
      echo "REFUSE: ansible check failed; not applying." >&2
      exit 8
    }
  fi

  ( cd "${CONTROLPLANE_STAGE_DIR}" && make apply ) || {
    receipt_note "controlplane update refused (apply failed)" tag="${tag}"
    echo "REFUSE: apply failed." >&2
    exit 9
  }
else
  echo "NOTE: controlplane venv missing; run: ${CP_DIR}/scripts/bootstrap_local.sh" >&2
  if [[ -n "${CONTROLPLANE_TARGET_TAG}" ]]; then
    receipt_note "controlplane update refused (venv missing)" tag="${tag}" dir="${CP_DIR}"
    echo "REFUSE: venv missing; cannot apply forced tag ${tag}." >&2
    exit 2
  fi
  receipt_note "controlplane update skipped (venv missing)" tag="${tag}" dir="${CP_DIR}"
  echo "SKIP: controlplane venv missing; not applying ${tag}." >&2
  exit 0
fi

# Only after a successful apply, update the live working tree to the same tag
git checkout -f "${tag}" >/dev/null 2>&1 || git checkout -f "tags/${tag}" >/dev/null 2>&1 || true

receipt_note "controlplane staged update+apply ok" tag="${tag}" dir="${CP_DIR}"
echo "OK: applied ${tag}"

# Reseal registry manifest after staged apply (device-bound)
/opt/aevum-tools/bin/aevum-registry-seal --base /var/lib/aevum/workstation --registry /etc/aevum/registry --tpm || true
