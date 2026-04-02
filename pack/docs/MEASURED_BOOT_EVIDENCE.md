# Measured Boot & Secure Boot Evidence — Local STRICT (v1)

This pack captures **boot integrity evidence** without turning boot into a fragile gate.

## What gets captured (best-effort)
1. Secure Boot posture:
- `mokutil --sb-state`
- `mokutil --list-enrolled` (saved as artifact)
- EFI `SecureBoot` variable hash
- `efibootmgr -v` output
- `bootctl status` (if systemd-boot)

2. Boot artifacts (hashes):
- `/boot/vmlinuz-$(uname -r)`
- `/boot/initrd.img-$(uname -r)`
- `/boot/grub/grub.cfg` and `grubenv` (if present)
- `/etc/default/grub`
- EFI binaries under `/boot/efi/EFI/**.efi` (bounded)

3. TPM evidence:
- Measured-boot eventlog(s) from `/sys/kernel/security/tpm0/*`
- PCR snapshot (sha256 bank by default)

4. A single tying snapshot:
- `boot_integrity_*.json` references the latest secureboot report + eventlog manifest + PCR snapshot by sha256.

## Services / timers
- `aevum-secureboot-capture.timer` (boot + daily)
- `aevum-tpm-eventlog-capture.timer` (boot + daily)
- `aevum-tpm-pcr-snapshot.timer` (boot + periodic)
- `aevum-boot-integrity-capture.timer` (boot + daily)

## Why this is safe
- **Non-gating**: failures do not prevent the machine from operating.
- Evidence is captured and receipted when available.

## UKI note
If you later switch to systemd-boot + UKI, the capture already inventories:
- `/boot/efi/EFI/Linux/*.efi` (detected as UKIs)
and hashes them as EFI binaries.
