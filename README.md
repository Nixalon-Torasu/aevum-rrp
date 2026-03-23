# Aevum Workstation Bootstrap — Hardened Repo Source

This repository is the **development source**. Installers MUST run from a **release zip** produced by the build scripts.

Quickstart (local)
```bash
./tools/install_hooks.sh
./tools/build_release_zip.sh v2_74
./tools/sign_release.sh dist/aevum_workstation_bootstrap_gitops_v2_74.zip
```

External-boot appliance kit
- See: `appliance/external_boot_kit/` (v0.2 TPM binding)
- This kit installs the pack onto a system booted from an external SSD and mounts internal “memory” at `/var/lib/aevum/workstation`.

Autoinstall scaffold
- See: `os/autoinstall/`
