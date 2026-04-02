#!/usr/bin/env bash
set -euo pipefail

# verify_pack.sh (STRICT)
#
# Purpose: verify the integrity of this unpacked bootstrap pack before install.
# It checks:
#  0) PACK_MANIFEST.meta.json binds the manifest (sha256(manifest) matches)
#  1) Every file listed in PACK_MANIFEST.sha256 matches its sha256 (STRICT parser)
#  2) There are no extra files not covered by the manifest (except the manifest + meta)
#
# This is a hard gate. If verification fails, installation MUST NOT continue.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="${ROOT}/PACK_MANIFEST.sha256"
META="${ROOT}/PACK_MANIFEST.meta.json"

cd "${ROOT}"

if [[ ! -f "${MANIFEST}" ]]; then
  echo "FAIL: ${MANIFEST} missing; cannot verify pack integrity." >&2
  echo "Refusing to install without a checksum manifest." >&2
  exit 2
fi

if [[ ! -f "${META}" ]]; then
  echo "FAIL: ${META} missing; cannot verify manifest binding." >&2
  exit 2
fi

echo "== Pack integrity (STRICT) =="
echo "manifest=${MANIFEST}"
echo "meta=${META}"

# 0) Verify meta binds to manifest
if command -v python3 >/dev/null 2>&1; then
  python3 - <<'PY'
import json,hashlib,sys
from pathlib import Path
root = Path(".")
meta = json.loads((root/"PACK_MANIFEST.meta.json").read_text(encoding="utf-8"))
mf = (root/"PACK_MANIFEST.sha256").read_bytes()
sha = hashlib.sha256(mf).hexdigest()
want = meta.get("manifest_sha256","")
if not want or want != sha:
    print(f"FAIL: meta.manifest_sha256 mismatch\n  meta={want}\n  actual={sha}", file=sys.stderr)
    sys.exit(2)
print(f"OK: meta binds manifest sha256:{sha}")
PY
else
  echo "FAIL: python3 missing; cannot verify meta binding." >&2
  exit 2
fi

# 1) Verify checksums (STRICT)
if ! sha256sum --strict -c "${MANIFEST}"; then
  echo "FAIL: pack integrity check failed against PACK_MANIFEST.sha256" >&2
  echo "If you intentionally modified files, re-package and regenerate PACK_MANIFEST." >&2
  exit 2
fi

# 2) Verify there are no extra files not covered by manifest
manifest_files="$(awk '{print $2}' "${MANIFEST}" | sed 's#\r$##')"

# Find all files in pack root excluding manifest + meta.
all_files="$(find . -type f ! -path './PACK_MANIFEST.sha256' ! -path './PACK_MANIFEST.meta.json' -printf '%p\n' | sed 's#^\./##')"

extra="$(comm -13 <(printf '%s\n' "${manifest_files}" | sort) <(printf '%s\n' "${all_files}" | sort) || true)"
missing="$(comm -23 <(printf '%s\n' "${manifest_files}" | sort) <(printf '%s\n' "${all_files}" | sort) || true)"

if [[ -n "${missing}" ]]; then
  echo "FAIL: manifest references missing files:" >&2
  echo "${missing}" >&2
  exit 2
fi

if [[ -n "${extra}" ]]; then
  echo "FAIL: pack contains files NOT covered by PACK_MANIFEST.sha256:" >&2
  echo "${extra}" >&2
  echo "Refusing to install (prevents silent drift / untracked artifacts)." >&2
  exit 2
fi

# Conical guard: prevent silent omission of critical pack paths
python3 "${ROOT}/gitops/conical_guard.py" --pack-root "${ROOT}"

# Print a single fingerprint for operator records
pack_fp="$(sha256sum "${MANIFEST}" | awk '{print $1}')"
echo "PASS: pack integrity verified"
echo "PACK_FINGERPRINT(sha256_of_manifest)=${pack_fp}"
