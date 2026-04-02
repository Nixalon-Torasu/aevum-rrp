# LUKS crypttab + initramfs helper (Plan-first)
This helper bridges: **LUKS2 volumes exist + TPM2 token enrolled** → **boot unlock configured**.

## Why plan-first
Editing `/etc/crypttab` and regenerating initramfs is a classic brick footgun. This tool defaults to producing a plan + evidence artifacts, and mints receipts describing the plan.

## Commands
- Plan (non-destructive):
  - `sudo /opt/aevum-tools/bin/aevum-luks-boot-helper`
- Apply (writes /etc/crypttab + runs update-initramfs):
  - `sudo /opt/aevum-tools/bin/aevum-luks-boot-helper --apply --i-understand`

## Inputs (registry)
- `/etc/aevum/registry/luks_devices.json` — list of device paths to manage
- `/etc/aevum/registry/luks_policy.json` — PCRs + default crypttab options

## Evidence artifacts
Written under:
- `/var/lib/aevum/workstation/boot/crypttab/`

Includes:
- `crypttab_plan_<ts>.json`
- `crypttab_planned_<ts>.txt`
- `cryptenroll_dump_<name>_<ts>.txt` (best-effort)
- `crypttab_apply_<ts>.json`
- `update_initramfs_<ts>.log`
- `crypttab_backup_<ts>.txt` (when applicable)

## Receipts
The helper mints:
- `crypttab_plan`
- `crypttab_apply`

Receipts inherit **sealed registry binding** automatically (printer-layer injection).
