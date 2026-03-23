#!/usr/bin/env bash
set -euo pipefail

# Aevum Workstation Postflight (v2.30)
# Non-destructive. Does NOT open egress. Does NOT change firewall state.

BASE="${BASE:-/var/lib/aevum/workstation}"
ID_PUB="${BASE}/identity/identity.public.json"
TLOG_LEGACY="${BASE}/receipts/T.jsonl"
TLOG_SEAM="${BASE}/accurate/receipts/T.jsonl"
BLOG_LEGACY="${BASE}/receipts/B.jsonl"
BLOG_SEAM="${BASE}/accurate/receipts/B.jsonl"

OK=1
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*" >&2; OK=0; }
warn() { echo "WARN: $*" >&2; }

echo "== Aevum Postflight =="
echo "base=${BASE}"

# Identity presence + self-signature (best-effort)
if [[ -f "${ID_PUB}" ]]; then
  pass "identity public present: ${ID_PUB}"
else
  if [[ -f "${BASE}/identity/identity.json" ]]; then
    warn "identity.public.json missing; identity.json present"
  else
    fail "identity missing under ${BASE}/identity"
  fi
fi

if command -v /usr/local/sbin/aevum_identity_bootstrap.py >/dev/null 2>&1; then
  /usr/local/sbin/aevum_identity_bootstrap.py --base /var/lib/aevum --instance workstation --verify-only >/dev/null 2>&1 \
    && pass "identity self-signature verifies" \
    || warn "identity verify-only not supported or failed (non-fatal)"
fi

# Services
svc() {
  local name="$1"
  if systemctl is-active --quiet "$name"; then pass "service active: $name"; else fail "service NOT active: $name"; fi
}
svc aevum-workstation-timechain.service
svc aevum-workstation-observer.service

# Timers (best-effort)
timer() {
  local name="$1"
  if systemctl is-enabled --quiet "$name"; then pass "timer enabled: $name"; else warn "timer not enabled: $name"; fi
}
timer aevum-controlplane-update.timer
timer aevum-workstation-journald-summary.timer
timer aevum-audit-summarize.timer
timer aevum-tpm-pcr-snapshot.timer
timer aevum-snapshot.timer
timer aevum-healthcheck.timer
timer aevum-workstation-module-harvest.timer
timer aevum-workstation-binary-harvest.timer

# Firewall locked (default deny egress)
if [[ -x /opt/aevum-tools/bin/aevum-firewallctl ]]; then
  out="$(/opt/aevum-tools/bin/aevum-firewallctl status 2>/dev/null || true)"
  echo "${out}" | grep -qi "egress.*CLOSED" && pass "egress closed" || warn "egress not clearly CLOSED (check firewallctl status)"
else
  warn "aevum-firewallctl not found; controlplane apply may have failed"
fi

# TimeChain log exists and has lines
TLOG=""
[[ -f "${TLOG_LEGACY}" ]] && TLOG="${TLOG_LEGACY}"
[[ -z "${TLOG}" && -f "${TLOG_SEAM}" ]] && TLOG="${TLOG_SEAM}"

if [[ -z "${TLOG}" ]]; then
  fail "TimeChain log not found (expected ${TLOG_LEGACY} or ${TLOG_SEAM})"
else
  lines="$(wc -l < "${TLOG}" 2>/dev/null || echo 0)"
  if [[ "${lines}" -ge 2 ]]; then pass "TimeChain log present (${lines} lines): ${TLOG}"; else warn "TimeChain log too small yet (${lines} lines)"; fi
fi

# Verifier quick check (hash-chain + optional sig)
if command -v /usr/local/sbin/aevum_verify.py >/dev/null 2>&1; then
  if [[ -n "${TLOG}" ]]; then
    if [[ -f "${ID_PUB}" ]]; then
      /usr/local/sbin/aevum_verify.py --base "${BASE}" --chain T --identity "${ID_PUB}" --warn-gaps >/dev/null 2>&1 \
        && pass "verifier: T chain PASS (with sig)" \
        || fail "verifier: T chain FAIL"
    else
      /usr/local/sbin/aevum_verify.py --base "${BASE}" --chain T --warn-gaps >/dev/null 2>&1 \
        && pass "verifier: T chain PASS (hash-only)" \
        || fail "verifier: T chain FAIL"
    fi
  fi
else
  warn "aevum_verify.py not installed"
fi

# Binary chain exists (best-effort)
if [[ -f "${BLOG_SEAM}" || -f "${BLOG_LEGACY}" ]]; then
  pass "Binary chain B present"
else
  warn "Binary chain B not present yet (it will appear after some execve activity)"
fi

# Bootstrap manifest
if [[ -f /etc/aevum/bootstrap_manifest.sha256 ]]; then
  pass "bootstrap manifest present: /etc/aevum/bootstrap_manifest.sha256 ($(cat /etc/aevum/bootstrap_manifest.sha256))"
else
  warn "bootstrap manifest missing: /etc/aevum/bootstrap_manifest.sha256"
fi

# TPM signing / anchor (best-effort)
if systemctl is-active --quiet aevum-tpm-sign-init.service; then
  pass "aevum-tpm-sign-init.service active"
else
  warn "aevum-tpm-sign-init.service not active (TPM may be absent)"
fi
if systemctl is-enabled --quiet aevum-tpm-anchor.timer; then
  pass "aevum-tpm-anchor.timer enabled"
else
  warn "aevum-tpm-anchor.timer not enabled"
fi
if ls /var/lib/aevum/workstation/tpm_sign/anchors/anchor_*.json >/dev/null 2>&1; then
  latest="$(ls -1 /var/lib/aevum/workstation/tpm_sign/anchors/anchor_*.json | sort | tail -n 1)"
  pass "TPM anchor artifact exists: ${latest}"
else
  warn "no TPM anchor artifacts yet"
fi

# Sysctl hardening
if systemctl is-enabled --quiet aevum-sysctl-apply.service; then
  pass "aevum-sysctl-apply.service enabled"
else
  warn "aevum-sysctl-apply.service not enabled"
fi

# TPM measured boot eventlog
if systemctl is-enabled --quiet aevum-tpm-eventlog-capture.timer; then
  pass "aevum-tpm-eventlog-capture.timer enabled"
else
  warn "aevum-tpm-eventlog-capture.timer not enabled"
fi
if ls /var/lib/aevum/workstation/boot/eventlog/manifest_*.json >/dev/null 2>&1; then
  latest="$(ls -1 /var/lib/aevum/workstation/boot/eventlog/manifest_*.json | sort | tail -n 1)"
  pass "eventlog manifest exists: ${latest}"
else
  warn "no eventlog manifests yet"
fi
if [[ -x /opt/aevum-tools/bin/aevum-tpm-eventlog-replay ]]; then
  pass "aevum-tpm-eventlog-replay installed"
else
  warn "aevum-tpm-eventlog-replay missing"
fi


# TPM PCR policy registry + pointers

# TPM receipt signing allowlist policy
if [[ -f /etc/aevum/registry/tpm_receipt_sign_policy.json ]]; then
  pass "tpm_receipt_sign_policy.json present"
else
  warn "tpm_receipt_sign_policy.json missing"
fi
if systemctl is-enabled --quiet aevum-tpm-receipt-policy-sync.timer; then
  pass "aevum-tpm-receipt-policy-sync.timer enabled"
else
  warn "aevum-tpm-receipt-policy-sync.timer not enabled"
fi
if [[ -f /var/lib/aevum/workstation/accurate/state/CURRENT_TPM_RECEIPT_SIGN_POLICY.json ]]; then
  h="$(sha256sum /var/lib/aevum/workstation/accurate/state/CURRENT_TPM_RECEIPT_SIGN_POLICY.json | awk '{print $1}')"
  pass "CURRENT_TPM_RECEIPT_SIGN_POLICY present (sha256:${h})"
else
  warn "CURRENT_TPM_RECEIPT_SIGN_POLICY missing"
fi

if [[ -f /etc/aevum/registry/tpm_pcr_policy.json ]]; then
  pass "tpm_pcr_policy.json present"
else
  warn "tpm_pcr_policy.json missing"
fi
if [[ -d /etc/aevum/registry/tpm_pcr_profiles ]]; then
  pass "tpm_pcr_profiles dir present"
else
  warn "tpm_pcr_profiles dir missing"
fi
if systemctl is-enabled --quiet aevum-tpm-policy-sync.timer; then
  pass "aevum-tpm-policy-sync.timer enabled"
else
  warn "aevum-tpm-policy-sync.timer not enabled"
fi
if [[ -f /var/lib/aevum/workstation/accurate/state/CURRENT_TPM_PCR_POLICY.json ]]; then
  h="$(sha256sum /var/lib/aevum/workstation/accurate/state/CURRENT_TPM_PCR_POLICY.json | awk '{print $1}')"
  pass "CURRENT_TPM_PCR_POLICY present (sha256:${h})"
else
  warn "CURRENT_TPM_PCR_POLICY missing (policy sync not run yet)"
fi

# Mint policy registry
if [[ -f /etc/aevum/registry/mint_policy.json ]]; then
  pass "mint_policy.json present"
else
  warn "mint_policy.json missing"
fi

echo "== Result =="
if [[ "${OK}" == "1" ]]; then
  echo "OVERALL: PASS (baseline)"
  exit 0
else
  echo "OVERALL: FAIL (see FAIL lines above)"
  exit 1
fi


echo ""
echo "=== Hardening helpers ==="
for t in aevum_secureboot_capture.py aevum_drift_scan.py aevum_apt_capture.py; do
  if [[ -x /usr/local/sbin/${t} ]]; then echo "PASS: ${t}"; else echo "FAIL: ${t} missing"; fail=1; fi
done
for t in aevum-apt-run aevum-luks-enroll-tpm2 aevum-podman-run aevum-lockdown; do
  if [[ -x /usr/local/sbin/${t} ]]; then echo "PASS: ${t}"; else echo "FAIL: ${t} missing"; fail=1; fi
done

if [[ -x /usr/local/sbin/aevum_controlplane_stage_update_apply.sh ]]; then echo "PASS: staged controlplane updater"; else echo "WARN: staged controlplane updater missing"; fi
