#!/usr/bin/env bash
set -euo pipefail

CFG="/etc/aevum/memory.json"
MOUNTPOINT="/var/lib/aevum/workstation"

require_root(){ [[ "$(id -u)" -eq 0 ]] || { echo "Run as root."; exit 2; }; }

boot_disk_name() {
  local root_src dm slave
  root_src="$(findmnt -n -o SOURCE / || true)"
  dm="$(readlink -f "${root_src}" 2>/dev/null || true)"
  if [[ "${dm}" == /dev/dm-* ]]; then
    slave="$(basename "$(ls -1 /sys/block/$(basename "${dm}")/slaves/* 2>/dev/null | head -n1)" 2>/dev/null || true)"
    lsblk -no PKNAME "/dev/${slave}" 2>/dev/null || true
  else
    lsblk -no PKNAME "${root_src}" 2>/dev/null || true
  fi
}

list_candidate_disks() {
  local bootdisk
  bootdisk="$(boot_disk_name)"
  lsblk -dpno NAME,SIZE,MODEL,RM,TYPE | awk '$5=="disk"{print}' | while read -r dev size model rm type; do
    local base
    base="$(basename "${dev}")"
    if [[ -n "${bootdisk}" && "${base}" == "${bootdisk}" ]]; then
      continue
    fi
    echo "${dev}|${size}|${model}|rm=${rm}"
  done
}

dedicated_disk_flow() {
  echo "Candidate disks (excluding boot disk):"
  mapfile -t CANDS < <(list_candidate_disks)
  if [[ "${#CANDS[@]}" -eq 0 ]]; then
    echo "ERROR: No candidate internal disks detected."
    exit 3
  fi
  local i
  for i in "${!CANDS[@]}"; do
    IFS='|' read -r dev size model rm <<<"${CANDS[$i]}"
    printf " [%d] %s  %s  %s  %s\n" "$i" "$dev" "$size" "$model" "$rm"
  done
  echo
  read -r -p "Select disk number to WIPE and use for Aevum memory: " idx
  [[ "${idx}" =~ ^[0-9]+$ ]] || { echo "Bad selection."; exit 2; }
  [[ "${idx}" -ge 0 && "${idx}" -lt "${#CANDS[@]}" ]] || { echo "Bad selection."; exit 2; }
  IFS='|' read -r DISK _ <<<"${CANDS[$idx]}"

  echo "YOU ARE ABOUT TO ERASE: ${DISK}"
  echo "To confirm, type exactly: ERASE ${DISK}"
  read -r -p "> " CONF
  [[ "${CONF}" == "ERASE ${DISK}" ]] || { echo "Cancelled."; exit 2; }

  apt-get update >/dev/null 2>&1 || true
  apt-get install -y cryptsetup gdisk jq >/dev/null 2>&1 || true

  sgdisk --zap-all "${DISK}"
  sgdisk -n1:0:0 -t1:8309 -c1:AEVUM_MEM "${DISK}"
  partprobe "${DISK}" || true
  sleep 1

  PART="$(lsblk -lnpo NAME "${DISK}" | sed -n '2p')"
  [[ -n "${PART}" ]] || { echo "ERROR: Could not find created partition."; exit 3; }

  echo "Creating LUKS2 on ${PART}..."
  cryptsetup luksFormat --type luks2 "${PART}"
  cryptsetup open "${PART}" aevum_mem
  mkfs.ext4 -L AEVUM_MEM /dev/mapper/aevum_mem

  mkdir -p /var/lib/aevum
  mkdir -p "${MOUNTPOINT}"

  LUKS_UUID="$(cryptsetup luksUUID "${PART}")"
  grep -q '^aevum_mem ' /etc/crypttab 2>/dev/null || echo "aevum_mem UUID=${LUKS_UUID} none luks,nofail" >> /etc/crypttab
  grep -q " ${MOUNTPOINT} " /etc/fstab 2>/dev/null || echo "/dev/mapper/aevum_mem ${MOUNTPOINT} ext4 defaults,noatime,nofail 0 2" >> /etc/fstab

  mount "${MOUNTPOINT}" || true

  jq -n --arg mode "luks_disk" --arg disk "${DISK}" --arg part "${PART}" --arg luks_uuid "${LUKS_UUID}" --arg mount "${MOUNTPOINT}" \
    '{mode:$mode,disk:$disk,partition:$part,luks_uuid:$luks_uuid,mountpoint:$mount}' > "${CFG}"
  chmod 600 "${CFG}"
  echo "OK: memory initialized and mounted at ${MOUNTPOINT}"
}

existing_path_flow() {
  echo "This option does NOT wipe disks."
  read -r -p "Enter an existing path on an internal drive (example: /mnt/data/aevum_memory): " P
  [[ -n "${P}" ]] || { echo "No path provided."; exit 2; }
  mkdir -p "${P}"
  mkdir -p /var/lib/aevum
  mkdir -p "${MOUNTPOINT}"
  grep -q " ${MOUNTPOINT} " /etc/fstab 2>/dev/null || echo "${P} ${MOUNTPOINT} none bind,nofail 0 0" >> /etc/fstab
  mount "${MOUNTPOINT}" || true
  jq -n --arg mode "bind_path" --arg path "${P}" --arg mount "${MOUNTPOINT}" \
    '{mode:$mode,path:$path,mountpoint:$mount}' > "${CFG}"
  chmod 600 "${CFG}"
  echo "OK: memory bind mount configured"
}

do_mount() {
  [[ -f "${CFG}" ]] || { echo "ERROR: ${CFG} not found. Run: aevum-memoryctl init"; exit 2; }
  mkdir -p "${MOUNTPOINT}"
  mount "${MOUNTPOINT}" || true
  echo "OK: mounted (best-effort)."
}

do_status() {
  echo "=== Aevum Memory Status ==="
  if [[ -f "${CFG}" ]]; then
    cat "${CFG}"
  else
    echo "No config at ${CFG}"
  fi
  echo
  findmnt "${MOUNTPOINT}" || echo "Not mounted: ${MOUNTPOINT}"
}

cmd="${1:-}"
require_root
case "${cmd}" in
  init)
    echo "Configure Aevum memory for ${MOUNTPOINT}"
    echo " [1] Dedicated internal disk (LUKS ext4)  [WIPES a disk]"
    echo " [2] Existing path bind mount            [NO wipe]"
    read -r -p "Choose 1 or 2: " CH
    case "${CH}" in
      1) dedicated_disk_flow;;
      2) existing_path_flow;;
      *) echo "Cancelled."; exit 2;;
    esac
    ;;
  mount) do_mount;;
  status) do_status;;
  *) echo "Usage: $0 {init|mount|status}"; exit 2;;
esac
