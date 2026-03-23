Aevum Workstation Bootstrap — Repo Hardened (v2_93)

This pack installs the Aevum-Workstation “printer”: tools + services + registries + policies that mint receipts and maintain a bounded observability spine.

Key operator commands:
  sudo aevum-bootstrap-update   # stages a 3-zip bundle (non-destructive)
  sudo aevum-bootstrap-apply    # applies staged bundle (bootkit → bootstrap → gitops)
  sudo aevum-modectl status|set <install|maintenance|locked|estop>

Docs:
  pack/docs/OPERATOR_DOCTRINE.md
  pack/docs/BUNDLE_CONTRACT.md

Notes:
- In locked mode, bundle signatures can be required (see contract doc).
- Firewall “locked” rules are never auto-enabled unless mode=locked.

