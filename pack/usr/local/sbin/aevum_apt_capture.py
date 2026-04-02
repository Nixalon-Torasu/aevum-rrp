#!/usr/bin/env python3

"""
aevum_apt_capture.py (v0.1)

Capture APT supply-chain surfaces (sources, keyrings, policies, cached repo metadata hashes).
Non-gating evidence for later audit/replay.

Writes under <base>/<instance>/supplychain/apt/<ts>/.
"""
from __future__ import annotations
import argparse, datetime as dt, hashlib, json, os, pathlib, subprocess, shutil
from typing import Dict, Any

def utc()->str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).strftime("%Y-%m-%dT%H:%M:%SZ")

def sha256_file(p:pathlib.Path)->str:
    h=hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

def run(cmd:list[str])->dict:
    try:
        p=subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return {"rc":p.returncode,"stdout":p.stdout,"stderr":p.stderr}
    except Exception as e:
        return {"rc":127,"stdout":"","stderr":str(e)}

def copy_tree(src:pathlib.Path, dst:pathlib.Path):
    if not src.exists(): 
        return
    if src.is_file():
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        return
    dst.mkdir(parents=True, exist_ok=True)
    for p in src.rglob("*"):
        if p.is_file():
            rel=p.relative_to(src)
            (dst/rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, dst/rel)

def main()->int:
    ap=argparse.ArgumentParser()
    ap.add_argument("--base", default="/var/lib/aevum")
    ap.add_argument("--instance", default="workstation")
    args=ap.parse_args()

    root=pathlib.Path(args.base)/args.instance
    ts=dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    outdir=root/"supplychain"/"apt"/ts
    outdir.mkdir(parents=True, exist_ok=True)

    report={"type":"aevum_apt_capture_v1","timestamp_utc":utc(),"instance":args.instance,"artifacts":{}, "commands":{}}

    # Copy sources lists and keyrings (best-effort)
    copy_tree(pathlib.Path("/etc/apt/sources.list"), outdir/"etc_apt"/"sources.list")
    copy_tree(pathlib.Path("/etc/apt/sources.list.d"), outdir/"etc_apt"/"sources.list.d")
    copy_tree(pathlib.Path("/etc/apt/trusted.gpg"), outdir/"etc_apt"/"trusted.gpg")
    copy_tree(pathlib.Path("/etc/apt/trusted.gpg.d"), outdir/"etc_apt"/"trusted.gpg.d")
    copy_tree(pathlib.Path("/etc/apt/keyrings"), outdir/"etc_apt"/"keyrings")

    # Cache metadata hashes (Release/InRelease files already downloaded)
    lists=pathlib.Path("/var/lib/apt/lists")
    meta={}
    if lists.exists():
        for p in lists.glob("*InRelease"):
            try:
                meta[str(p.name)]="sha256:"+sha256_file(p)
            except Exception:
                pass
        for p in lists.glob("*Release"):
            try:
                meta[str(p.name)]="sha256:"+sha256_file(p)
            except Exception:
                pass
    report["artifacts"]["apt_lists_meta"]=meta

    # dpkg inventory
    dpkg = run(["bash","-lc","dpkg-query -W -f '${Package}\t${Version}\t${Architecture}\n'"])
    (outdir/"dpkg.tsv").write_text(dpkg["stdout"], encoding="utf-8")
    report["commands"]["dpkg_query"]={"rc":dpkg["rc"],"stderr":dpkg["stderr"]}

    pol = run(["bash","-lc","apt-cache policy"])
    (outdir/"apt_policy.txt").write_text(pol["stdout"] + "\n\nSTDERR:\n" + pol["stderr"], encoding="utf-8")
    report["commands"]["apt_cache_policy"]={"rc":pol["rc"]}

    # hashes of stored files
    filehash={}
    for p in outdir.rglob("*"):
        if p.is_file():
            try:
                filehash[str(p.relative_to(outdir))]="sha256:"+sha256_file(p)
            except Exception:
                pass
    report["artifacts"]["files"]=filehash

    (outdir/"CAPTURE.json").write_text(json.dumps(report, indent=2, sort_keys=True)+"\n", encoding="utf-8")
    os.chmod(outdir/"CAPTURE.json", 0o600)

    receipt=pathlib.Path("/opt/aevum-tools/bin/aevum-receipt")
    if receipt.exists() and os.access(receipt, os.X_OK):
        subprocess.run([str(receipt),"note","apt supply-chain capture","component=supplychain","dir="+str(outdir)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print(f"OK: {outdir}")
    return 0

if __name__=="__main__":
    raise SystemExit(main())
