#!/usr/bin/env bash
set -euo pipefail

VERSION="${1:-}"
if [[ -z "${VERSION}" ]]; then
  echo "Usage: $0 <version-tag-like-v2_74>"
  exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACK_DIR="${REPO_ROOT}/pack"
WORK_DIR="${REPO_ROOT}/work"
DIST_DIR="${REPO_ROOT}/dist"

mkdir -p "${WORK_DIR}" "${DIST_DIR}"

# Tightening: only build from a clean worktree
"${REPO_ROOT}/tools/verify_worktree_clean.sh"

# Tightening: regenerate manifest from git-tracked files only
python3 "${REPO_ROOT}/tools/generate_pack_manifest.py" --repo-root "${REPO_ROOT}" --pack-dir "pack"

# Stage export: copy ONLY git-tracked files under pack/
STAGE="${WORK_DIR}/stage_${VERSION}_$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "${STAGE}"

# Copy tracked files (including manifests we just generated)
while IFS= read -r -d '' f; do
  rel="${f#pack/}"
  mkdir -p "${STAGE}/$(dirname "${rel}")"
  cp -a "${REPO_ROOT}/${f}" "${STAGE}/${rel}"
done < <(git -C "${REPO_ROOT}" ls-files -z 'pack/*')

# Strict verify in staged directory (no .git present)
if [[ -x "${STAGE}/gitops/verify_pack.sh" ]]; then
  (cd "${STAGE}" && bash gitops/verify_pack.sh)
else
  echo "ERROR: verify_pack.sh missing in staged export"
  exit 3
fi

OUT_ZIP="${DIST_DIR}/aevum_workstation_bootstrap_gitops_${VERSION}.zip"
rm -f "${OUT_ZIP}"
(cd "${STAGE}" && zip -qr "${OUT_ZIP}" .)

echo "OK: ${OUT_ZIP}"
