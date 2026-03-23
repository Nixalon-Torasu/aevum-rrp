== AEVUM WORKSTATION BOOTSTRAP PATCH NOTES v2_93 ==

Major changes:
- Bundle-aware update/apply pipeline:
  - `aevum-bootstrap-update` stages a bundle manifest from exactly 3 zips (bootkit/bootstrap/gitops).
  - `aevum-bootstrap-apply` applies the staged bundle in order and re-verifies before changing the system.
- Introduced operator mode state machine (install/maintenance/locked/estop) with `aevum-modectl`.
- Added operator docs:
  - pack/docs/OPERATOR_DOCTRINE.md
  - pack/docs/BUNDLE_CONTRACT.md

Behavioral changes:
- `aevum-bootstrap-update` is now staging-only by default (no auto-apply).
  Use `--apply` if you want the legacy behavior.

