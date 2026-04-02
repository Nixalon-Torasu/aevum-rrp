#!/usr/bin/env bash
set -euo pipefail
# --- v2_74: create Core boundary identity (aevum-core) ---
if ! getent group aevum-core >/dev/null; then
  groupadd --system aevum-core || true
fi
if ! id -u aevum-core >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin -g aevum-core aevum-core || true
fi


# Aevum Workstation GitOps Bootstrap (v2_74)
# Goal: drop this repo on a fresh Ubuntu 24.04 Server (minimal) and run this script.
# It installs:
# - receipt spine tools + systemd units
# - bounded audit rules (execve-focused) + harvest timers
# - locked default-deny egress firewall (controlplane-managed)
# - TPM helpers (best-effort) and measured-boot artifacts (best-effort)
# - a local controlplane git repo (seeded and applied locally)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

require_root() { [[ "$(id -u)" -eq 0 ]] || { echo "Run as root (sudo)"; exit 2; }; }
require_root

echo "=== Aevum Workstation Bootstrap ==="
echo "repo_root=${REPO_ROOT}"

# Pack integrity verification (MANDATORY; hard gate)
if [[ "${AEVUM_PACK_VERIFY:-1}" == "1" ]]; then
  bash "${SCRIPT_DIR}/verify_pack.sh"
else
  # Bypass is intentionally hard: require explicit acknowledgement.
  if [[ "${AEVUM_ALLOW_UNVERIFIED_PACK:-0}" != "1" ]]; then
    echo "FAIL: pack verification disabled but AEVUM_ALLOW_UNVERIFIED_PACK=1 not set." >&2
    echo "Refusing to install an unverified pack." >&2
    exit 2
  fi
  echo "WARN: installing with pack verification DISABLED (operator override)." >&2
fi


echo "[1/9] Packages (baseline)"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y \
  git python3 python3-venv python3-cryptography \
  nftables auditd rsyslog \
  tpm2-tools openssl mokutil fwupd \
  btrfs-progs zstd \
  gnupg pinentry-curses \
  podman podman-compose slirp4netns uidmap fuse-overlayfs \
  linux-firmware \
  pciutils usbutils dmidecode lshw hwloc numactl \
  lm-sensors i2c-tools nvme-cli smartmontools hdparm ethtool \
  rasdaemon edac-utils \
  chrony jq curl wget ca-certificates rsync unzip zip \
  || true

echo "[git] Configure default identity (local-only placeholder; change later if you want)"
if [ -n "${SUDO_USER:-}" ] && id "$SUDO_USER" >/dev/null 2>&1; then
  sudo -u "$SUDO_USER" git config --global user.name "${SUDO_USER}" || true
  sudo -u "$SUDO_USER" git config --global user.email "${SUDO_USER}@aevum.local" || true
  sudo -u "$SUDO_USER" git config --global init.defaultBranch main || true
else
  git config --system user.name "aevum" || true
  git config --system user.email "aevum@localhost" || true
  git config --system init.defaultBranch main || true
fi


echo "[2/9] Persistent journald"
mkdir -p /var/log/journal
sed -i 's/^#Storage=.*/Storage=persistent/' /etc/systemd/journald.conf || true
systemctl restart systemd-journald || true

echo "[3/9] Directories"
install -d -m 0700 /var/lib/aevum
install -d -m 0755 /opt
install -d -m 0755 /opt/aevum-tools/bin
install -d -m 0755 /run/aevum || true

echo "[4/9] Install Aevum receipt spine tools"

echo "[4.5/9] (Deferred) Registry signing will run after configs are installed"
install -m 0755 "${REPO_ROOT}/bin/"*.py /usr/local/sbin/
install -m 0755 "${REPO_ROOT}/bin/"*.sh /usr/local/sbin/ || true

# bootstrap lifecycle commands (no .sh extension)
install -m 0755 "/bin/aevum-bootstrap-update" /usr/local/sbin/aevum-bootstrap-update
install -m 0755 "/bin/aevum-bootstrap-apply"  /usr/local/sbin/aevum-bootstrap-apply
# hardening helpers
install -m 0755 "${REPO_ROOT}/bin/aevum-apt-run" /usr/local/sbin/aevum-apt-run 2>/dev/null || true
install -m 0755 "${REPO_ROOT}/bin/aevum-luks-enroll-tpm2" /usr/local/sbin/aevum-luks-enroll-tpm2 2>/dev/null || true
install -m 0755 "${REPO_ROOT}/bin/aevum-podman-run" /usr/local/sbin/aevum-podman-run 2>/dev/null || true
install -m 0755 "${REPO_ROOT}/bin/aevum-lockdown" /usr/local/sbin/aevum-lockdown 2>/dev/null || true

install -m 0755 "${REPO_ROOT}/bin/aevum-gpgctl" /usr/local/sbin/aevum-gpgctl 2>/dev/null || true
install -m 0755 "${REPO_ROOT}/bin/aevum-bundle-install" /usr/local/sbin/aevum-bundle-install 2>/dev/null || true
install -m 0755 "${REPO_ROOT}/bin/aevum_controlplane_update_apply.sh" /usr/local/sbin/aevum_controlplane_update_apply.sh 2>/dev/null || true

echo "[5/9] Install /opt/aevum-tools toolset"
for f in "${REPO_ROOT}/opt/aevum-tools/bin/"*; do
  [[ -f "$f" ]] || continue
  install -m 0755 "$f" "/opt/aevum-tools/bin/$(basename "$f")" || true
done

# Install TPM helpers into /opt
for f in "${REPO_ROOT}/bin"/aevum-tpm-*; do
  if [[ -f "$f" ]]; then install -m 0755 "$f" "/opt/aevum-tools/bin/$(basename "$f")" || true; fi
done


echo "[5.7/9] Install RRP smoketest helper"
if [[ -f "${REPO_ROOT}/bin/aevum_rrp_smoketest.sh" ]]; then
  install -m 0755 "${REPO_ROOT}/bin/aevum_rrp_smoketest.sh" /usr/local/sbin/aevum_rrp_smoketest.sh || true
  install -d -m 0755 /opt/aevum-tools/bin || true
  cat > /opt/aevum-tools/bin/aevum-rrp-smoketest <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exec /usr/local/sbin/aevum_rrp_smoketest.sh "$@"
EOF
  chmod 0755 /opt/aevum-tools/bin/aevum-rrp-smoketest
fi

echo "[6/9] Seed controlplane repo (local git)"
if [[ ! -d /opt/aevum-controlplane ]]; then
  cp -a "${REPO_ROOT}/controlplane/aevum-workstation-controlplane" /opt/aevum-controlplane
  cd /opt/aevum-controlplane
  git init
  git config user.name  "${AEVUM_GIT_NAME:-Aevum Workstation}"
  git config user.email "${AEVUM_GIT_EMAIL:-aevum-workstation@local}"
  git add -A
  git commit -m "seed: aevum workstation controlplane" || true
  echo "Seeded /opt/aevum-controlplane (git init + initial commit)."
else
  echo "NOTE: /opt/aevum-controlplane already exists; leaving as-is."
fi

echo "[6.5/9] Bootstrap controlplane venv + apply (local)"
if [[ -d /opt/aevum-controlplane ]]; then
  cd /opt/aevum-controlplane
  ./scripts/bootstrap_local.sh || true
  if [[ -x .venv/bin/ansible-playbook ]]; then
    # Apply baseline roles (includes firewall + tools)
    source .venv/bin/activate || true
    make apply || true
  fi
fi


echo "[7/9] Install configuration files"
install -d -m 0755 /etc/aevum
install -m 0644 "${REPO_ROOT}/etc/aevum/ssh_allow_cidrs" /etc/aevum/ssh_allow_cidrs 2>/dev/null || true
install -m 0644 "${REPO_ROOT}/etc/aevum/firewall_mode" /etc/aevum/firewall_mode 2>/dev/null || true
install -d -m 0755 /etc/aevum/registry
install -d -m 0755 /etc/tmpfiles.d || true
install -m 0644 "${REPO_ROOT}/etc/tmpfiles.d/aevum.conf" /etc/tmpfiles.d/aevum.conf || true
systemd-tmpfiles --create /etc/tmpfiles.d/aevum.conf 2>/dev/null || true
install -m 0644 "${REPO_ROOT}/etc/aevum/registry/rrp_policy.json" /etc/aevum/registry/rrp_policy.json || true
install -m 0644 "${REPO_ROOT}/etc/aevum/registry/core_clients.json" /etc/aevum/registry/core_clients.json || true
install -d -m 0755 /etc/aevum/trustedkeys.d
install -d -m 0755 /etc/aevum/bundles.d
install -d -m 0755 /etc/aevum/egress_profiles.d
install -d -m 0700 /etc/aevum/gnupg || true

# bounded configs
install -m 0644 "${REPO_ROOT}/etc/aevum/binary_harvest.conf" /etc/aevum/binary_harvest.conf || true
install -m 0644 "${REPO_ROOT}/etc/aevum/registry/mint_policy.json" /etc/aevum/registry/mint_policy.json || true
install -m 0644 "${REPO_ROOT}/etc/aevum/registry/tpm_pcr_policy.json" /etc/aevum/registry/tpm_pcr_policy.json || true
install -m 0644 "${REPO_ROOT}/etc/aevum/registry/tpm_receipt_sign_policy.json" /etc/aevum/registry/tpm_receipt_sign_policy.json || true
install -m 0644 "${REPO_ROOT}/etc/aevum/registry/registry_deprecations.json" /etc/aevum/registry/registry_deprecations.json || true
mkdir -p /etc/aevum/registry/tpm_pcr_profiles || true
if [[ -d "${REPO_ROOT}/etc/aevum/registry/tpm_pcr_profiles" ]]; then cp -a "${REPO_ROOT}/etc/aevum/registry/tpm_pcr_profiles/." /etc/aevum/registry/tpm_pcr_profiles/ || true; fi

# bundles + egress profiles (optional use)
cp -a "${REPO_ROOT}/etc/aevum/bundles.d/." /etc/aevum/bundles.d/ 2>/dev/null || true
cp -a "${REPO_ROOT}/etc/aevum/egress_profiles.d/." /etc/aevum/egress_profiles.d/ 2>/dev/null || true


echo "[7.9/9] Firewall handoff: apply SAFE mode by default (install)."
FW_MODE="${AEVUM_FIREWALL_MODE:-install}"
# Never apply locked mode over SSH unless explicitly allowed (prevents self-brick).
if [[ -n "${SSH_CONNECTION:-}" && "$FW_MODE" == "locked" && "${AEVUM_ALLOW_LOCKED_OVER_SSH:-0}" != "1" ]]; then
  echo "WARN: Refusing to apply locked firewall over SSH. Forcing install mode."
  FW_MODE="install"
fi
# Ensure ssh_allow_cidrs exists (if install file was missing)
if [[ ! -f /etc/aevum/ssh_allow_cidrs ]]; then
  echo -e "10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16" > /etc/aevum/ssh_allow_cidrs
  chmod 0644 /etc/aevum/ssh_allow_cidrs || true
fi
if [[ -x /opt/aevum-tools/bin/aevum-firewallctl ]]; then
  /opt/aevum-tools/bin/aevum-firewallctl "$FW_MODE" || true
fi

# Initialize GPG allowlist dir (used by GitOps signature checks)
if [[ -x /usr/local/sbin/aevum-gpgctl ]]; then
  /usr/local/sbin/aevum-gpgctl init || true
fi

echo "[8/9] Workstation identity + baseline services"
# Always-identified workstation
/usr/local/sbin/aevum_identity_bootstrap.py --base /var/lib/aevum --instance workstation --seam-layout || true

# Bootstrap manifest (dpkg + hardware snapshot) — evidence, not a gate
TS_BOOT="$(date -u +%Y%m%dT%H%M%SZ)"
BOOTDIR="/var/lib/aevum/workstation/bootstrap"
mkdir -p "${BOOTDIR}"
dpkg-query -W -f '${Package}\t${Version}\t${Architecture}\n' > "${BOOTDIR}/dpkg_${TS_BOOT}.tsv" || true
lscpu > "${BOOTDIR}/lscpu_${TS_BOOT}.txt" 2>/dev/null || true
lspci -nnk > "${BOOTDIR}/lspci_${TS_BOOT}.txt" 2>/dev/null || true
lsblk -o NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,MODEL,SERIAL > "${BOOTDIR}/lsblk_${TS_BOOT}.txt" 2>/dev/null || true
SHA_DPKG="$(sha256sum "${BOOTDIR}/dpkg_${TS_BOOT}.tsv" | awk '{print $1}')" || true
if [[ -x /opt/aevum-tools/bin/aevum-receipt ]]; then
  /opt/aevum-tools/bin/aevum-receipt note "bootstrap manifest" component=bootstrap dpkg="sha256:${SHA_DPKG}" || true
fi

echo "[8.2/9] Install systemd units"
install -m 0644 "${REPO_ROOT}/systemd/"*.service /etc/systemd/system/
install -m 0644 "${REPO_ROOT}/systemd/"*.timer /etc/systemd/system/ 2>/dev/null || true
systemctl daemon-reload

echo "[8.3/9] Install audit rules + sysctl hardening (bounded)"
if [[ -d /etc/audit/rules.d ]]; then
  install -m 0640 "${REPO_ROOT}/etc/audit/aevum.rules" /etc/audit/rules.d/aevum.rules
  install -m 0640 "${REPO_ROOT}/etc/audit/aevum_root.rules" /etc/audit/rules.d/aevum_root.rules || true
  install -m 0640 "${REPO_ROOT}/etc/audit/aevum_all.rules" /etc/audit/rules.d/aevum_all.rules || true
  install -m 0640 "${REPO_ROOT}/etc/audit/aevum_privileged.rules" /etc/audit/rules.d/aevum_privileged.rules || true
  install -m 0644 "${REPO_ROOT}/etc/sysctl.d/99-aevum-hardening.conf" /etc/sysctl.d/99-aevum-hardening.conf || true
  systemctl enable --now aevum-sysctl-apply.service || true
  augenrules --load || true
  systemctl restart auditd.service || true
fi

echo "[8.35/9] Preflight gate (systemd ExecStart targets exist)"
bash "${SCRIPT_DIR}/preflight_systemd_gate.sh" \
  aevum-sysctl-apply.service \
  aevum-registry-seal.service \
  aevum-workstation-timechain.service \
  aevum-workstation-observer.service \
  aevum-workstation-journald-summary.timer \
  aevum-workstation-module-harvest.timer \
  aevum-workstation-binary-harvest.timer \
  aevum-controlplane-update.timer \
  aevum-healthcheck.timer \
  aevum-snapshot.timer \
  aevum-egress-observe-collect.timer \
  aevum-audit-summarize.timer \
  aevum-drift-scan.timer \
  aevum-apt-capture.timer \
  aevum-registry-verify.timer \
  aevum-boot-unlock-evidence.service \
  aevum-verify-continuity.timer \
  aevum-rrp-printerd.service \
  aevum-hw-inventory.timer \
  aevum-secureboot-capture.timer \
  aevum-tpm-sign-init.service \
  aevum-tpm-anchor.timer \
  aevum-tpm-eventlog-capture.timer \
  aevum-tpm-ak-init.timer \
  aevum-tpm-pcr-snapshot.timer \
  aevum-tpm-policy-sync.timer \
  aevum-tpm-receipt-policy-sync.timer \
  aevum-docker-policy.service \
  aevum-segment.timer
echo "[8.4/9] Enable baseline services and timers"
systemctl enable --now aevum-registry-seal.service
systemctl enable --now aevum-workstation-timechain.service
systemctl enable --now aevum-workstation-observer.service
systemctl enable --now aevum-workstation-journald-summary.timer
systemctl enable --now aevum-workstation-module-harvest.timer
systemctl enable --now aevum-workstation-binary-harvest.timer

systemctl enable --now aevum-controlplane-update.timer
systemctl enable --now aevum-healthcheck.timer
systemctl enable --now aevum-snapshot.timer
systemctl enable --now aevum-egress-observe-collect.timer
systemctl enable --now aevum-audit-summarize.timer

systemctl enable --now aevum-drift-scan.timer
systemctl enable --now aevum-apt-capture.timer
systemctl enable --now aevum-registry-verify.timer
systemctl enable --now aevum-boot-unlock-evidence.service
systemctl enable --now aevum-verify-continuity.timer
systemctl enable --now aevum-rrp-printerd.service
systemctl enable --now aevum-hw-inventory.timer
systemctl enable --now aevum-secureboot-capture.timer


# TPM helpers (best-effort)
systemctl start aevum-tpm-sign-init.service || true
systemctl enable --now aevum-tpm-anchor.timer || true
systemctl enable --now aevum-tpm-eventlog-capture.timer || true
systemctl enable --now aevum-tpm-ak-init.timer || true
systemctl enable --now aevum-tpm-pcr-snapshot.timer || true
systemctl enable --now aevum-tpm-policy-sync.timer || true
systemctl enable --now aevum-tpm-receipt-policy-sync.timer || true
/opt/aevum-tools/bin/aevum-tpm-receipt-policy sync || true
# Prime policy pointers and emit receipts if needed
/opt/aevum-tools/bin/aevum-tpm-policy sync || true

# Container policy baseline (best-effort)
systemctl enable --now aevum-docker-policy.service || true
systemctl enable --now aevum-segment.timer || true

echo "[8.6/9] Bootstrap manifest (deployed hashes)"
mkdir -p /etc/aevum
{
  echo "# Aevum bootstrap manifest (meta)"
  echo "# generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  (cd /opt/aevum-controlplane && git rev-parse HEAD 2>/dev/null | awk '{print "controlplane_git_head="$1}') || true
} > /etc/aevum/bootstrap_manifest.meta

tmpm="$(mktemp)"
( find /usr/local/sbin -maxdepth 1 -type f -name 'aevum_*' -print0 2>/dev/null | xargs -0r sha256sum ) >> "${tmpm}" || true
( find /etc/systemd/system -maxdepth 1 -type f -name 'aevum-*.*' -print0 2>/dev/null | xargs -0r sha256sum ) >> "${tmpm}" || true
( find /etc/aevum -type f -print0 2>/dev/null | xargs -0r sha256sum ) >> "${tmpm}" || true
sha256sum "${tmpm}" | awk '{print $1}' > /etc/aevum/bootstrap_manifest.sha256
rm -f "${tmpm}" || true

if [[ -x /opt/aevum-tools/bin/aevum-receipt ]]; then
  manhash="$(cat /etc/aevum/bootstrap_manifest.sha256 2>/dev/null || echo '')"
  /opt/aevum-tools/bin/aevum-receipt note "bootstrap manifest written" component=bootstrap manifest="sha256:${manhash}" || true
fi

echo "[8.9/9] Postflight (non-fatal)"
sleep 2
bash "${SCRIPT_DIR}/postflight_check.sh" || true

echo "[9/9] Done"
echo ""
echo "Optional next steps (bundles):"
echo "  sudo aevum-bundle-install essentials"
echo "  sudo aevum-bundle-install observability"
echo "  sudo aevum-bundle-install podman"
echo "  sudo aevum-bundle-install nvidia    # may require SecureBoot MOK"
echo "  sudo aevum-bundle-install tika"
echo ""
echo "Controlplane repo: /opt/aevum-controlplane (git)"
echo "Receipts base:     /var/lib/aevum/workstation"
echo "Receipt CLI:       sudo aevum_receipts.py --base /var/lib/aevum/workstation stats --chain T"
echo ""
ln -sfn /opt/aevum-controlplane /opt/ai-stack || true
