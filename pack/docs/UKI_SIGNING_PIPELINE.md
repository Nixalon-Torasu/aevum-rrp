# UKI Build + Signing Pipeline (Optional) — Workstation Evidence Layer
**Canonical ID:** AEVUM:BOOT:UKI:PIPELINE:LOCAL_STRICT:V1_0  
**Version:** 1.0.0  
**Date:** 2026-02-04  
**Status:** Implementation-grade (non-gating by default)

## Purpose
Provide a safe, optional pipeline to:
1) Build a Unified Kernel Image (UKI) for the currently installed kernel.
2) Optionally sign it for Secure Boot (typically via shim/MOK).
3) Emit receipts that bind the resulting boot artifact identity into Aevum’s evidence layer.

This is **not** a boot gate by default. It is evidence + reproducibility scaffolding.

## Tools installed by this pack (best-effort)
- `ukify` (preferred) — may come from `systemd-ukify` depending on distro packaging
- `sbsign`/`sbverify` from `sbsigntool`
- `openssl`

## Commands
### 1) Generate a signing keypair (RSA) for UKI signing (MOK-style)
```
sudo /opt/aevum-tools/bin/aevum-uki-keygen
```
Outputs:
- `/etc/aevum/secureboot/keys/uki_signing.key` (root-only)
- `/etc/aevum/secureboot/keys/uki_signing.crt`
- `/etc/aevum/secureboot/keys/uki_signing.der` (for mokutil import)

### 2) Enroll the cert via mokutil (interactive)
```
sudo mokutil --import /etc/aevum/secureboot/keys/uki_signing.der
```
Reboot and complete MOK enrollment in firmware UI.

### 3) Build UKI (unsigned) or build+sign
Unsigned:
```
sudo /opt/aevum-tools/bin/aevum-uki-build --unsigned
```
Signed (requires sbsign + enrolled cert):
```
sudo /opt/aevum-tools/bin/aevum-uki-build --sign
```

Output location (default):
- `/boot/efi/EFI/Linux/aevum-uki-<uname-r>.efi`
- `/boot/efi/EFI/Linux/aevum-uki-<uname-r>.signed.efi`

Artifacts:
- `/var/lib/aevum/workstation/boot/uki/uki_manifest_<ts>.json`

A receipt is minted that references the manifest by sha256 pointer (pointers-over-payloads).

## Notes
- This pack does **not** automatically change your boot order or add a firmware boot entry.
- You can add one manually via `efibootmgr` after validating your UKI.
- You can choose to keep GRUB and only use UKI as an alternate boot target.

## Why this matters for Aevum
UKIs make “boot identity” crisp:
- kernel + initrd + cmdline + stub are unified
- the UKI file digest becomes a strong boot artifact reference
- Secure Boot signing adds a firm chain-of-custody signal

## Adopt UKI (create EFI boot entry)
Use the workstation helper to create a firmware boot entry pointing at the UKI and optionally adjust BootOrder/BootNext.

Examples:
```bash
# Create entry for latest signed UKI, do not change BootOrder
sudo /opt/aevum-tools/bin/aevum-uki-bootentry

# Create entry and set it first in BootOrder
sudo /opt/aevum-tools/bin/aevum-uki-bootentry --set-first

# One-time boot into the UKI
sudo /opt/aevum-tools/bin/aevum-uki-bootentry --set-bootnext
```

Evidence and receipts:
- Writes `/var/lib/aevum/workstation/boot/efi/bootentry_change_<ts>.json` and stores `efibootmgr -v` snapshots (before/after).
- Mints a receipt referencing the manifest (registry-binding injected automatically).
