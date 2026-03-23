# Aevum Workstation Clean Install Protocol (Ubuntu 24.04 Server Minimal)

This repo is designed to support a **full wipe + deterministic reinstall**.  
Goal: **fresh OS + reproducible foundation + receipts minting immediately**.

## Scope
- Target OS: **Ubuntu 24.04 Server (minimal install)**
- Network model: **default-deny**, bounded egress windows for installs/updates
- Containers: **Podman-first**
- Receipts: **non-governing** (never block kernel/package/config), minted as the machine operates

## What you keep vs wipe
For a full clean install: **wipe everything**.
Optional (only if you want continuity): export these *before* wipe:
- `/var/lib/aevum/**` (receipts/artifacts)
- `/etc/aevum/**` (policy/config)
- `/etc/nftables.d/**` (firewall profiles)
- `/etc/audit/rules.d/aevum.rules` (audit policy)

If you do NOT export them, this install remains valid and self-contained.

## BIOS/firmware recommendations (practical)
- Enable TPM2 if you intend to use TPM sealing later
- Decide Secure Boot policy up front (NVIDIA drivers may require MOK enrollment)
- Ensure UEFI boot mode

## Installation steps (fresh OS)
1. Install Ubuntu 24.04 Server (minimal)
2. Log in as an admin user, then:
   ```bash
   sudo -i
   apt-get update
   apt-get install -y unzip
   ```
3. Copy this repo zip to the machine (USB or scp), then:
   ```bash
   mkdir -p aevum_workstation_bootstrap_gitops_v2_74
   unzip aevum_workstation_bootstrap_gitops_v2_74.zip -d aevum_workstation_bootstrap_gitops_v2_74
   cd aevum_workstation_bootstrap_gitops_v2_74/gitops
   sudo bash ./install_workstation_gitops.sh
   ```
4. Postflight (PASS/FAIL):
   ```bash
   sudo bash ./postflight_check.sh
   ```


## Pack integrity gate (mandatory)
The installer **refuses to run** unless `PACK_MANIFEST.sha256` verifies and there are **no extra/untracked files** in the pack directory.

Override (not recommended):
```bash
AEVUM_PACK_VERIFY=0 AEVUM_ALLOW_UNVERIFIED_PACK=1 sudo bash ./install_workstation_gitops.sh
```

## Determinism & assurance checks
The installer writes a bootstrap manifest:
- `/etc/aevum/bootstrap_manifest.sha256`
This captures hashes of the installed scripts/configs so you can prove what was deployed.

## Factory reset (without reinstalling OS)
If you need a “wipe the Aevum layer” reset on an already-installed OS:
```bash
sudo /opt/aevum-tools/bin/aevum-factory-reset
```
This stops/disables Aevum services and removes Aevum state/configs (does not touch OS packages).


## Pack integrity + TPM anchoring
- Run `bash gitops/verify_pack.sh` before install (installer does this by default).
- TPM signing creates a TPM-resident ECC key and emits TPM-signed anchor artifacts (does not replace Ed25519 receipt signing).


## Hardening pack
- Sysctl hardening applied via `aevum-sysctl-apply.service`.
- Audit mode switch: `sudo aevum-audit-mode set root_only|all_exec`.
- Kernel modules are audited and harvested into chain M.
- TPM quotes: anchors now embed a TPM quote; verify with `sudo aevum-tpm-verify-anchor <anchor.json>`.


## Measured boot evidence
This pack captures the TPM measured-boot eventlog (when available) and binds it into TPM anchor artifacts. Use `aevum-tpm-verify-anchor` to verify the embedded quote; eventlog verification is best-effort depending on tpm2-tools support.


## Deterministic measured-boot replay
The pack includes `aevum-tpm-eventlog-replay`, a pure-Python parser/replayer for TPM2 measured boot eventlogs.
It recomputes SHA-256 PCR values from the captured eventlog and can be used to cross-check quoted PCR values even if your `tpm2_checkquote` does not support `--eventlog`.


## TimeChain TBV1 delta roots
TimeChain now commits per-second *delta* Merkle roots for other chains by reading new JSONL lines since a stored cursor.
This keeps the foundation purely commitment-based while enabling fast higher-order views in aevum-core.


## Workstation Mint Gate policy
`/etc/aevum/registry/mint_policy.json` is hashed into each TimeBlock (TBV1) as `mint_policy_sha256`.
This binds the mint rules (bounded taxonomy / anti token-collapse posture) into the attested history.


# Hardening roadmap (v2.40)

## Disk encryption + TPM binding (recommended)
- Install Ubuntu with **LUKS2** (root and/or a dedicated /var/lib/aevum volume).
- After first boot, enroll TPM2:
  - `sudo aevum-luks-enroll-tpm2 --root --pcrs 0,2,7`
  - Or for a data volume: `sudo aevum-luks-enroll-tpm2 --device /dev/<luksdev>`
- PCR guidance:
  - PCR7 binds to SecureBoot state; firmware updates and kernel signing changes can rotate PCRs.
  - PCR0/2 bind to firmware/bootloader; tighter = stronger but more brittle.

## Secure Boot posture evidence
- `aevum-secureboot-capture.timer` records mokutil status, EFI SecureBoot var, and bootctl status.
- If you install NVIDIA drivers under SecureBoot, you likely need a MOK enrollment flow.

## Supply-chain capture
- Use `sudo aevum-apt-run update|install ...` to open a bounded egress window and automatically capture APT state.
- Daily APT capture runs via `aevum-apt-capture.timer`.

## Drift detection
- `aevum-drift-scan.timer` hashes control surfaces and records changes for audit.
- Optional lock: `sudo aevum-lockdown enable` (uses chattr +i; reversible).

## Containers
- Use `aevum-podman-run` as the safe-default launcher.


## TPM PCR Policy
The workstation uses a bounded PCR selection policy in `/etc/aevum/registry/tpm_pcr_policy.json`.
This policy is receipted and mirrored to `/var/lib/aevum/workstation/accurate/state/CURRENT_TPM_PCR_POLICY.json` by `aevum-tpm-policy-sync.timer`.
TPM quotes, PCR snapshots, TPM anchors, and TimeChain blocks embed the policy hash.

### TPM PCR Policy Profiles
Profiles are shipped under `/etc/aevum/registry/tpm_pcr_profiles/` and can be applied with:

```bash
sudo /opt/aevum-tools/bin/aevum-tpm-policy profiles
sudo /opt/aevum-tools/bin/aevum-tpm-policy apply baseline_observe "initial workstation policy"
```

Policy transitions emit an explicit `tpm_pcr_policy_transition` receipt containing `from_policy_sha256`, `to_policy_sha256`, and the method/profile/reason.

## Selective TPM receipt signing
Receipts are always signed with the device **Ed25519** key. The TPM is **not** used to sign every receipt by default (the TPM would become a throughput bottleneck).
Instead:
- The TPM signs **per-second TimeChain commitments** (time blocks).
- The TPM optionally signs a bounded allowlist of **high-value** receipts (policy/key/controlplane/import) via an allowlist policy.

Policy:
- `/etc/aevum/registry/tpm_receipt_sign_policy.json`

Manage:
```bash
sudo /opt/aevum-tools/bin/aevum-tpm-receipt-policy show
sudo /opt/aevum-tools/bin/aevum-tpm-receipt-policy set --enabled true --max-per-second 2 --allow-components "identity,gpg,controlplane,import_gate,tpm_policy,tpm_policy_transition" --reason "tighten allowlist"
sudo /opt/aevum-tools/bin/aevum-tpm-receipt-policy sync
```

What it does:
- When a receipt matches the allowlist, `aevum_receiptctl.py` adds a `tpm_signature` object into the envelope (best-effort).
- TimeChain includes `tpm_receipt_sign_policy_sha256` so policy drift is visible.
