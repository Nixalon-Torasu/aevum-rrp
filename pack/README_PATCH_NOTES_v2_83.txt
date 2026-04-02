Aevum Workstation Bootstrap — Hardened Pack v2_83
====================================================

Fixes / Hardening
- Fix: identity private key loading now supports disk-stored PKCS8 PEM at:
    identity.json -> keys.device_signing_key.storage.private_key_path
  and continues to support embedded private_key_b64 (legacy).
  Also normalizes subject_id_hex / capture_device_hex lookup to device.* / subject.* / machine.* fallbacks.

- Fix: aevum-verify
  - Seam-first receipt root selection (prefer base/accurate/receipts when both layouts exist).
  - --log now works without requiring --chain (no accidental empty-chain segment scan).
  - Payload verification now resolves payload_ref correctly for Seam (base/accurate/payloads/...) and legacy.

- Fix: aevum-verify-continuity
  - Detects TimeChain log at base/(accurate/receipts)/T.jsonl (Seam) instead of base/timechain/timechain.jsonl.
  - Calls bundled verifier with --chain T.
  - Loads payload via payload_ref when envelope does not embed payload.
  - Missing TimeChain log is SKIP (exit 0) because the unit is non-gating.

- Fix: preflight_systemd_gate.sh
  - Timer Unit= extraction no longer hard-fails under set -euo pipefail when Unit= is absent (awk-based extraction).

- Hardening: aevum-ima-snapshot
  - Systemd unit gated by ConditionPathExists=/sys/kernel/security/ima/ascii_runtime_measurements
  - Script treats missing IMA as SKIP (exit 0) (non-gating).

- Hardening: aevum_firewall.py
  - Graceful error if nft is not installed (returns 127 with clear message).

Packaging
- Normalized executable bits on pack scripts (bin/, usr/local/sbin/, opt/aevum-tools/bin/, gitops/) for direct execution workflows.
- PACK_MANIFEST regenerated accordingly.

Smoketest
- Added/updated smoketest report (separate JSON artifact):
  aevum_service_smoketest_v2_83.json
