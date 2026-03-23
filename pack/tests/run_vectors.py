#!/usr/bin/env python3
from __future__ import annotations
import pathlib, shutil, subprocess, tempfile

ROOT = pathlib.Path(__file__).resolve().parent
BIN = ROOT.parent / "bin"

def run(cmd, cwd=None):
    p = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return p.returncode, p.stdout

def verify(case: pathlib.Path, chain: str, expect_ok: bool) -> bool:
    base = case/"base"
    ident = case/"identity.public.json"
    cmd = ["python3", str(BIN/"aevum_verify.py"), "--base", str(base), "--chain", chain, "--identity", str(ident)]
    rc, out = run(cmd)
    ok = (rc == 0)
    print(f"[verify] {case.name} chain={chain} rc={rc} expect_ok={expect_ok}")
    if ok != expect_ok:
        print(out)
        return False
    return True

def recover_then_verify(case: pathlib.Path, chain: str) -> bool:
    with tempfile.TemporaryDirectory(prefix="aevum_vec_") as td:
        tcase = pathlib.Path(td)/case.name
        shutil.copytree(case, tcase)
        base = tcase/"base"
        ident = tcase/"identity.public.json"
        rc, out = run(["python3", str(BIN/"aevum_recover.py"), "--base", str(base), "--repair"])
        print(f"[recover] rc={rc}")
        if rc != 0:
            print(out); return False
        rc2, out2 = run(["python3", str(BIN/"aevum_verify.py"), "--base", str(base), "--chain", chain, "--identity", str(ident)])
        print(f"[verify-after] rc={rc2}")
        if rc2 != 0:
            print(out2); return False
    return True

def main() -> int:
    V = ROOT/"vectors"
    ok = True
    ok &= verify(V/"case_good", "T", True)
    ok &= verify(V/"case_bad_prevhash", "T", False)
    ok &= verify(V/"case_tail_trunc", "T", False)
    ok &= recover_then_verify(V/"case_tail_trunc", "T")
    ok &= verify(V/"case_segmented_good", "T", True)
    return 0 if ok else 2

if __name__ == "__main__":
    raise SystemExit(main())
