# Proof-grade unlock method (Aevum Workstation)

## What "proof-grade" means here
Linux does not expose a signed primitive saying "TPM was used" for LUKS unlock.
So Aevum defines a **proof-grade boundary**:

> If the system is configured so *passphrase prompting cannot occur*, then a successful boot that results in unlocked volumes implies TPM unlock.

This is not a claim about physics; it is a claim about an enforced boot configuration and the evidence we store.

## Required conditions for `tpm2_proof`
Aevum will classify a volume unlock as `tpm2_proof` when ALL are true:

1. `unlock_mode == tpm2_only` in `/etc/aevum/registry/luks_policy.json`
2. Ask-password units are **masked** (symlink to `/dev/null`) and initramfs rebuilt
   - `systemd-ask-password-console.*`
   - `systemd-ask-password-wall.*`
3. Volume is unlocked (`/dev/mapper/<name>` exists)
4. LUKS metadata at boot contains a TPM2 token
5. LUKS metadata digest at boot matches the enroll-time expected digest stored in:
   - `/var/lib/aevum/workstation/luks/tokens/expected_tokens.json`

If passphrase prompts appear in logs, classification becomes `passphrase`.

## Workflow
1) Enroll TPM2 token:
- `aevum-luks-enroll-tpm2 --device /dev/... --pcrs 0,2,7`
  - captures token snapshot
  - updates expected token metadata digests (state + receipt)

2) Configure boot (plan-first):
- `aevum-luks-boot-helper` (plan)
- `aevum-luks-boot-helper --apply --i-understand` (apply)
  - in `tpm2_only` mode it masks ask-password units and rebuilds initramfs

3) On each boot:
- `aevum-boot-unlock-evidence.service` captures hashed artifacts and emits a receipt.

## Notes
- `tpm2_only` is deliberately harsh: if TPM unseal fails, boot will fail rather than prompting.
- Use `tpm2_prefer` during experimentation.


## Proof-grade verifier enforcement
In `unlock_mode=tpm2_only`, verification can enforce the invariant across all recorded boot evidence:

- `aevum-verify --strict --check-boot-unlock`
- `aevum-verify-evidence --strict --dir /var/lib/aevum/workstation/boot/unlock`

Strict mode fails if any evidence reports a non-`tpm2_proof` method or an unlocked==false volume.
