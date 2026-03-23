# LUKS2 + TPM2 Sealing (Non-Bricking) — Workstation Boundary
**Canonical ID:** AEVUM:BOOT:LUKS_TPM:LOCAL_STRICT:V1_0  
**Version:** 1.0.0  
**Date:** 2026-02-04  
**Status:** Implementation-grade

## Goal
Provide disk-boundary hardening that:
- Uses **LUKS2** for at-rest encryption
- Uses **TPM2** to *seal* a LUKS unlock token to PCR policy (measured boot)
- Emits **receipts** for: header identity, enrollment policy, and evidence snapshots
- Does **not** brick the system by default (all operations are explicit)

## Non-Bricking defaults
- No automatic disk formatting.
- No automatic boot changes.
- No automatic crypttab/initramfs modification.
- Tools default to **plan-only** output unless `--execute --i-understand-this-wipes-data` is provided.

## Components shipped
- `aevum-luks-init` (plan/execute luksFormat + open + optional filesystem create)
- `aevum-luks-enroll-tpm` (systemd-cryptenroll TPM2 token enrollment)
- `aevum-luks-snapshot` (hash header region + capture luksDump + token summary + PCR snapshot refs)
- systemd timer for periodic snapshots (non-gating)

## What is receipted
Receipts are minted by the Workstation printer and automatically include **sealed registry binding**.
Each LUKS action mints a receipt with pointers to artifacts under:
`/var/lib/aevum/workstation/luks/`

### Header identity
We compute `luks_header_region_sha256` as SHA-256 over the first `header_region_bytes` of the block device (default 16 MiB).

### TPM enrollment evidence
We record:
- PCR list used (`tpm2_pcrs`)
- systemd-cryptenroll output (artifact + sha256 pointer)
- optional `tpm2_pcrread` snapshot reference (if available)

## Recommended PCR set (practical)
Default: `0+2+7`
- 0: Core firmware/CRTM
- 2: Option ROMs
- 7: Secure Boot policy state

You may expand later, but start here; too many PCRs makes upgrades painful.

## Verifier
`aevum-verify --check-luks` verifies latest luks snapshot artifact integrity (hashes match) and validates that referenced files exist.
