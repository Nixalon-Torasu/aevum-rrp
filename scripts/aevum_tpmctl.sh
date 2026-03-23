#!/usr/bin/env bash
set -euo pipefail

# aevum-tpmctl: TPM2 binding for the EXTERNAL BOOT root LUKS device
#
# Commands:
#   status      - show TPM presence + systemd-cryptenroll dump for root LUKS
#   bind-root   - enroll a TPM2 token into root LUKS (PCR 7)
#   wipe-root   - remove TPM2 enrollment from root LUKS
#
# Notes:
# - This uses systemd-cryptenroll. You may be prompted for your LUKS passphrase.

require_root(){ [[ "$(id -u)" -eq 0 ]] || { echo "Run as root."; exit 2; }; }
require_root

root_mapper_name() {
  local src
  src="$(findmnt -n -o SOURCE / || true)"
  if [[ "${src}" == /dev/mapper/* ]]; then
    basename "${src}"
  else
    echo ""
  fi
}

root_luks_device() {
  # Return underlying LUKS block device for /
  local mapper dev
  mapper="$(root_mapper_name)"
  if [[ -z "${mapper}" ]]; then
    echo ""
    return
  fi
  dev="$(cryptsetup status "${mapper}" 2>/dev/null | awk -F': ' '/device:/ {print $2; exit}')"
  echo "${dev}"
}

have_tpm() {
  [[ -c /dev/tpmrm0 || -c /dev/tpm0 || -d /sys/class/tpm/tpm0 ]]
}

do_status() {
  echo "=== TPM status ==="
  if have_tpm; then
    echo "TPM: PRESENT"
  else
    echo "TPM: NOT DETECTED"
  fi
  echo
  local dev
  dev="$(root_luks_device)"
  if [[ -z "${dev}" ]]; then
    echo "Root: not detected as /dev/mapper/* (no LUKS root?)"
    exit 0
  fi
  echo "Root LUKS device: ${dev}"
  if ! cryptsetup isLuks "${dev}" >/dev/null 2>&1; then
    echo "Root device is not LUKS."
    exit 0
  fi
  echo
  systemd-cryptenroll --dump "${dev}" || true
}

do_bind() {
  local dev
  dev="$(root_luks_device)"
  if [[ -z "${dev}" ]]; then
    echo "ERROR: root LUKS device not found. Is / on LUKS?"
    exit 3
  fi
  if ! have_tpm; then
    echo "SKIP: TPM not detected."
    exit 0
  fi
  if ! cryptsetup isLuks "${dev}" >/dev/null 2>&1; then
    echo "ERROR: ${dev} is not LUKS."
    exit 3
  fi
  echo "Enrolling TPM2 token into root LUKS (${dev}) using PCR 7..."
  systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7 "${dev}"
  update-initramfs -u
  echo "OK: TPM2 enrollment done."
}

do_wipe() {
  local dev
  dev="$(root_luks_device)"
  if [[ -z "${dev}" ]]; then
    echo "ERROR: root LUKS device not found."
    exit 3
  fi
  if ! cryptsetup isLuks "${dev}" >/dev/null 2>&1; then
    echo "ERROR: ${dev} is not LUKS."
    exit 3
  fi
  echo "Removing TPM2 enrollment from root LUKS (${dev})..."
  systemd-cryptenroll --wipe-slot=tpm2 "${dev}" || true
  update-initramfs -u
  echo "OK: TPM2 enrollment removed (if present)."
}

cmd="${1:-}"
case "${cmd}" in
  status) do_status;;
  bind-root) do_bind;;
  wipe-root) do_wipe;;
  *) echo "Usage: aevum-tpmctl {status|bind-root|wipe-root}"; exit 2;;
esac
