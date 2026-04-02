AEVUM PATCH NOTES v2_96 (CANONICALIZATION / CONTROLPLANE MINIMIZATION)

Goal:
- Remove "mutable evidence collectors" drift.
- Make bootstrap/bootkit the authority for tools; GitOps/controlplane may update policy/config only.

Changes:
1) Fixed a critical packaging violation:
   - systemd units execute /usr/local/sbin/*, but several executables previously lived only in pack/bin
     (and some were being backfilled by controlplane patch roles).
   - v2_96 moves all systemd-executed executables into pack/usr/local/sbin, so bootstrap-apply installs them deterministically.

2) Removed bootkit-owned operator commands from the bootstrap pack:
   - Removed from pack/usr/local/sbin:
       aevum-bootstrap-apply
       aevum-bootstrap-update
       aevum-modectl
       aevum-uki-keygen
   Reason: these are the bootkit/operator surface and MUST NOT be overwritten by bootstrap.

3) Removed duplicate tool copies and their controlplane installers:
   - Deleted duplicate tool copies under:
       pack/controlplane/.../roles/aevum_tools_patch/files/*
       pack/controlplane/.../roles/aevum_layout/files/aevum-*.{service,timer}
   - Trimmed corresponding Ansible tasks so controlplane no longer installs/patches executables or systemd units.

4) Regenerated gitops/release_cone_required_paths.json:
   - Required path cone is now anchored on canonical pack surfaces:
     gitops/, systemd/, usr/local/sbin/, opt/aevum-tools/bin/, controlplane/, etc/aevum/.

Operational impact:
- Controlplane no longer mutates evidence-collecting executables. Tool changes must ship via bootstrap pack.
- This is a prerequisite for strict, auditable, deterministic receipts.

