Aevum Workstation Bootstrap Hardened v2_82 (patch over v2_81)

This patch adds an install-time SYSTEMD EXEC TARGET GATE to prevent “enabled-but-broken” services.

Key additions/changes:
- Install-time systemd gate:
  * New: pack/gitops/preflight_systemd_gate.sh
  * Called by install_workstation_gitops.sh before enabling any Aevum services/timers.
  * Validates that every enabled unit’s ExecStart*/ExecStop/ExecReload executable exists on the host.
  * Expands timers -> their corresponding service units (via Unit= or default .service mapping).
  * Refuses to continue if any targets are missing (hard fail), preventing silent swiss-cheese installs.

- Enable behavior tightened:
  * Removed “|| true” from baseline `systemctl enable --now ...` calls (core services/timers are now required to enable cleanly).
  * Best-effort hardware units remain best-effort (TPM, etc.), but their ExecStart targets are still gated for presence.

Operator overrides (explicit, noisy):
  - Disable gate entirely:
      AEVUM_SYSTEMD_GATE=0
  - Allow missing targets but continue (NOT recommended):
      AEVUM_ALLOW_MISSING_SYSTEMD_TARGETS=1
