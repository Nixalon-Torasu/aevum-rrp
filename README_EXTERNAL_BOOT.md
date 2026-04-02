Version: v0_7

# Aevum External-Boot Appliance Kit (v0.6 — TPM Binding)

This kit makes your **external SSD** the **boot OS ("brain")** and uses an **internal disk/path** on the host machine as **Aevum memory** (receipts + payloads + segments).

## Design intent
- External SSD contains: Ubuntu OS + Aevum software + models + appliance identity + bind policy.
- Internal disk/path contains: **/var/lib/aevum/workstation** (receipts/payloads/state) so the machine’s hardware provides durable “memory”.
- If you unplug the external SSD, the machine does not boot into Aevum.
- If you plug the external SSD into another machine:
  - **TPM binding prevents auto-unlock**, and
  - a **bind gate** prevents Aevum services from running unless you prepared a move.

## What you run
After you boot Ubuntu from the external SSD:
  sudo ./AEVUM_EXTERNAL_BOOT_SETUP.sh

## Files included
- AEVUM_EXTERNAL_BOOT_SETUP.sh          : main setup script (runs on external-booted Ubuntu)
- scripts/aevum_memoryctl.sh           : create/mount memory (internal disk or existing path)
- scripts/aevum_tpmctl.sh              : TPM bind/unbind root LUKS (systemd-cryptenroll)
- scripts/aevum_bind_gate.sh           : binding enforcement at boot (quarantine mode)
- scripts/aevum_token.py               : move-token create/verify (signed)
- systemd/aevum-bind-gate.service      : systemd unit for bind gate
- systemd/aevum-quarantine.target      : minimal “do nothing” target for unbound boot
- systemd/aevum-quarantine.service     : prints console message + best-effort network down
- bin/aevum-appliance                  : operator CLI (status/evidence/prepare-move/rebind/tpm-status)

-------------------------------------------------------------------------------
## 0) One-time: install Ubuntu onto the EXTERNAL SSD (boot OS)
-------------------------------------------------------------------------------

A) Create a Ubuntu installer USB (Ubuntu 24.04 Server).
B) Boot the installer on the target machine.
C) Install Ubuntu onto the EXTERNAL SSD (do not touch internal disks).
D) Enable encryption (LUKS) for the external SSD if offered (recommended).
E) Reboot; set BIOS/UEFI boot device to the external SSD.

-------------------------------------------------------------------------------
## 1) Copy files onto the external SSD (while booted from it)
-------------------------------------------------------------------------------

Put these in the same folder on the external SSD:
- aevum_workstation_bootstrap_gitops_v2_74.zip
- this kit folder (or at least AEVUM_EXTERNAL_BOOT_SETUP.sh)

Recommended:
  /opt/aevum-external-kit/

-------------------------------------------------------------------------------
## 2) Run setup
-------------------------------------------------------------------------------

  cd /opt/aevum-external-kit
  sudo ./AEVUM_EXTERNAL_BOOT_SETUP.sh

This will:
- verify your pack (strict drift prevention)
- create appliance identity (for move tokens)
- configure internal “memory” at /var/lib/aevum/workstation
- run the v2_74 installer
- install bind gate + quarantine
- enroll TPM unlock for the external root LUKS (if TPM present)
- generate an evidence bundle

-------------------------------------------------------------------------------
## 3) Binding + Move
-------------------------------------------------------------------------------

Normal: bound to this host.
  sudo aevum-appliance status

Prepare move (MUST run before unplugging):
  sudo aevum-appliance prepare-move
This will:
  - stop Aevum services
  - create a signed move token (24h)
  - **remove TPM binding for root** so the external disk can be unlocked by passphrase on the new machine

On the new machine (boot external SSD, enter LUKS passphrase), then:
  sudo aevum-appliance rebind
This will:
  - validate the move token
  - bind to the new host fingerprint
  - re-enroll TPM unlock for root (if TPM present)
  - (you then re-run memory setup for the new machine)

TPM status:
  sudo aevum-appliance tpm-status

-------------------------------------------------------------------------------
## 4) Safety notes
-------------------------------------------------------------------------------

- Memory init can wipe a disk if you choose the dedicated disk option.
  It forces a typed confirmation string.
- If TPM is not present, the kit falls back to fingerprint binding gate only.
- Keep your external SSD LUKS passphrase safe — it’s required for migration.


## Important

- This ZIP is the **External Boot Kit** (installer helper). It is **not** a Workstation bootstrap zip and does **not** contain `pack/`.
- Do **not** run `aevum-bootstrap-update` on this zip. Use the boot kit entrypoints in this repository (`AEVUM_EXTERNAL_BOOT_SETUP.sh` / `bootkit/`).
- Once Ubuntu is installed, use the Workstation bootstrap zip (contains `pack/`) and run:
  - `sudo aevum-bootstrap-update` (updates `/srv/aevum-hot/bootstrap/current`)
  - `sudo aevum-bootstrap-apply` (applies to the live system)
  - or one-shot: `sudo AEVUM_BOOTSTRAP_APPLY=1 AEVUM_FIREWALL_MODE=install aevum-bootstrap-update`
