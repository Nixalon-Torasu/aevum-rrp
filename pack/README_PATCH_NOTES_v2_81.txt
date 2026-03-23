Aevum Workstation Bootstrap Hardened v2_81 (patch over v2_80)

This pack repairs correctness and integrity gaps discovered during inspection.

Key fixes:
- Pack integrity:
  * Eliminated checksum self-reference: PACK_MANIFEST.sha256 now hashes pack content excluding PACK_MANIFEST.{sha256,meta.json}.
  * PACK_MANIFEST.meta.json binds the manifest via manifest_sha256.
  * verify_pack.sh upgraded to STRICT mode (sha256sum --strict), validates meta binding, blocks extras, then runs conical guard.

- Missing runtime tools:
  * Added /opt/aevum-tools/bin:
      aevum-audit-summarize
      aevum-egress-observe-collect
      aevum-snapshot-create
      aevum-dockerctl
      aevum-egress-profile-run
      aevum-egressctl / aevum-ingressctl
      aevum-state-snapshot
      aevum-tpm-eventlog-replay
      aevum-tpm-ak-init / aevum-tpm-eventlog-capture (order-independence)

- Script correctness:
  * Removed a leading stray backslash that broke shebang/bash execution in multiple controlplane scripts.
  * aevum_firewallctl.py rewritten to correctly set /etc/aevum/firewall_mode and apply rules; adds bounded egress window helper.
  * aevum_timechain_daemon.py: sha256 helpers now return hexdigest string (not hash object).

- GitOps / controlplane safety:
  * aevum_bundle_install.sh: exports variables into manifest generator; captures apt rc; no longer swallows failures; receipts warn on errors.
  * aevum_controlplane_stage_update_apply.sh: SKIP if venv missing; REFUSE if forced tag is requested without venv.
  * aevum_controlplane_update_apply.sh: no false "ok" receipts; exits non-zero on apply failures; skip/refuse semantics tightened.

Verification:
- pack/gitops/verify_pack.sh MUST pass before install (it is the install gate).

