#!/usr/bin/env python3
"""tools/generate_pack_manifest.py

Deterministic pack integrity manifest generator.

Design goal: avoid self-referential checksum cycles.

Outputs (under pack/):
  - PACK_MANIFEST.sha256
      sha256 lines for *content files* under pack/ (git-tracked),
      excluding:
        * PACK_MANIFEST.sha256 (this file)
        * PACK_MANIFEST.meta.json (metadata about the manifest)
  - PACK_MANIFEST.meta.json
      metadata that binds the manifest (includes sha256 of PACK_MANIFEST.sha256)

Guarantees:
  - Only git-tracked files under pack/ are included.
  - If untracked files exist under pack/, this tool fails.
  - Stable ordering of manifest entries (lexicographic paths).

Verifier expectations:
  - gitops/verify_pack.sh verifies meta->manifest binding, then checks all content hashes,
    then asserts there are no extra files outside the manifest except the manifest+meta themselves.
"""

from __future__ import annotations
import argparse
import hashlib
import json
import pathlib
import subprocess
import sys
import datetime as dt


def run(cmd: list[str], cwd: pathlib.Path) -> str:
    p = subprocess.run(cmd, cwd=str(cwd), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if p.returncode != 0:
        raise RuntimeError(p.stderr.strip() or f"command failed: {cmd}")
    return p.stdout


def sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo-root", default=".", help="repo root")
    ap.add_argument("--pack-dir", default="pack", help="pack directory")
    args = ap.parse_args()

    repo = pathlib.Path(args.repo_root).resolve()
    pack = (repo / args.pack_dir).resolve()
    if not pack.is_dir():
        print(f"ERROR: pack dir not found: {pack}", file=sys.stderr)
        return 2

    # Ensure we are in a git repo
    _ = run(["git", "rev-parse", "--is-inside-work-tree"], cwd=repo)

    # Fail if pack has untracked files
    pack_rel = pack.relative_to(repo).as_posix()
    untracked = run(["git", "ls-files", "--others", "--exclude-standard", pack_rel], cwd=repo).strip().splitlines()
    if any(u.strip() for u in untracked):
        print("ERROR: untracked files exist under pack/. Refusing to build.", file=sys.stderr)
        for u in untracked:
            if u.strip():
                print(f"  UNTRACKED: {u}", file=sys.stderr)
        return 3

    # List tracked files under pack/
    tracked = run(["git", "ls-files", "-z", pack_rel], cwd=repo).encode("utf-8")
    files = [p.decode("utf-8") for p in tracked.split(b"\x00") if p]
    files = [f for f in files if f.startswith(pack_rel + "/")]

    rel_manifest = f"{pack_rel}/PACK_MANIFEST.sha256"
    rel_meta = f"{pack_rel}/PACK_MANIFEST.meta.json"

    # Exclude manifest + meta from hashing (break checksum cycles)
    files_for_hash = [f for f in files if f not in (rel_manifest, rel_meta)]

    lines: list[str] = []
    for rel in sorted(files_for_hash):
        p = (repo / rel).resolve()
        if p.is_dir():
            continue
        digest = sha256_file(p)
        # verifier expects paths relative to pack root
        pack_path = pathlib.Path(rel).relative_to(pack_rel).as_posix()
        lines.append(f"{digest}  {pack_path}")

    manifest_path = pack / "PACK_MANIFEST.sha256"
    meta_path = pack / "PACK_MANIFEST.meta.json"

    manifest_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    manifest_sha = sha256_file(manifest_path)

    meta = {
        "schema_id": "AEVUM:PACK:MANIFEST_META:V2",
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat(),
        "git_commit": run(["git", "rev-parse", "HEAD"], cwd=repo).strip(),
        "git_describe": run(["git", "describe", "--tags", "--always", "--dirty"], cwd=repo).strip(),
        "hash_alg": "sha256",
        "manifest_file": "PACK_MANIFEST.sha256",
        "manifest_sha256": manifest_sha,
        "file_count": len(lines),
        "scope": "git-tracked content files under pack/ (excluding manifest+meta)",
    }
    meta_path.write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print("OK: wrote pack/PACK_MANIFEST.sha256 and pack/PACK_MANIFEST.meta.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
