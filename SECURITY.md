# Security posture (repo-level)

This repository is the **source-of-truth** for building **release packs**.
The installer MUST run only on a **clean, staged export** (no `.git/`), verified by:
- PACK_MANIFEST.sha256
- strict "no extra files" rule

Recommended controls
- Build only from a clean worktree.
- Export only git-tracked files from `pack/`.
- Sign release zips (GPG or minisign).
- Treat access control to the appliance as a separate "admission gate" design; do not rely on obscurity.
