#!/usr/bin/env python3
"""
aevum_uki_bootentry.py — Optional UKI adoption helper (non-gating)
Creates an EFI boot entry for a built UKI and optionally adjusts BootOrder/BootNext.
Also writes evidence artifacts and mints a receipt (workstation printer) referencing those artifacts.

Requires: efibootmgr, lsblk, findmnt
"""
import argparse, json, os, pathlib, re, subprocess, sys, hashlib, datetime
from typing import Dict, Any, Optional, Tuple, List

def run(cmd: List[str], check=True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=check)

def sha256_file(p: pathlib.Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

def sha256_text(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

def utc_now() -> str:
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")

def find_latest_uki() -> pathlib.Path:
    base = pathlib.Path("/boot/efi/EFI/Linux")
    if not base.exists():
        raise FileNotFoundError("missing /boot/efi/EFI/Linux (is ESP mounted at /boot/efi?)")
    signed = sorted(base.glob("*.signed.efi"), key=lambda p: p.stat().st_mtime, reverse=True)
    if signed:
        return signed[0]
    efi = sorted(base.glob("*.efi"), key=lambda p: p.stat().st_mtime, reverse=True)
    if efi:
        return efi[0]
    raise FileNotFoundError("no UKI .efi files found under /boot/efi/EFI/Linux")

def esp_source() -> str:
    p = run(["findmnt","-n","-o","SOURCE","/boot/efi"], check=True)
    src = p.stdout.strip()
    if not src:
        raise RuntimeError("cannot detect ESP source device via findmnt")
    return src

def disk_and_part(partdev: str) -> Tuple[str,int]:
    # partdev like /dev/nvme0n1p1 or /dev/sda1
    # derive disk: lsblk -no PKNAME
    pk = run(["lsblk","-no","PKNAME",partdev], check=True).stdout.strip()
    if not pk:
        raise RuntimeError(f"cannot derive parent disk for {partdev}")
    disk = "/dev/" + pk
    # part number: for nvme: endswith p<digits>; else digits at end
    m = re.search(r"p(\d+)$", partdev)
    if m:
        return disk, int(m.group(1))
    m = re.search(r"(\d+)$", partdev)
    if m:
        return disk, int(m.group(1))
    raise RuntimeError(f"cannot derive partition number from {partdev}")

def efi_loader_path(uki_path: pathlib.Path) -> str:
    # Convert /boot/efi/EFI/Linux/foo.efi -> \EFI\Linux\foo.efi
    up = str(uki_path)
    if not up.startswith("/boot/efi/"):
        raise ValueError("UKI path must be under /boot/efi")
    rel = up[len("/boot/efi/"):]
    rel = rel.replace("/", "\\")
    return "\\" + rel

def parse_bootorder(efibootmgr_out: str) -> List[str]:
    m = re.search(r"BootOrder:\s*([0-9A-Fa-f,]+)", efibootmgr_out)
    if not m:
        return []
    return [x.strip().upper() for x in m.group(1).split(",") if x.strip()]

def create_boot_entry(disk: str, part: int, label: str, loader: str, dry_run: bool) -> Tuple[Optional[str], str]:
    cmd = ["efibootmgr","--create","--disk",disk,"--part",str(part),"--label",label,"--loader",loader]
    if dry_run:
        return None, "DRY_RUN: " + " ".join(cmd)
    p = run(cmd, check=False)
    out = p.stdout
    # try parse created bootnum
    # efibootmgr typically prints "BootXXXX* <label>"
    m = re.search(r"Boot([0-9A-Fa-f]{4})\*", out)
    bootnum = m.group(1).upper() if m else None
    return bootnum, out

def set_bootnext(bootnum: str, dry_run: bool) -> str:
    cmd = ["efibootmgr","--bootnext",bootnum]
    if dry_run:
        return "DRY_RUN: " + " ".join(cmd)
    return run(cmd, check=False).stdout

def set_bootorder_first(bootnum: str, before_order: List[str], dry_run: bool) -> str:
    order = [bootnum] + [x for x in before_order if x != bootnum]
    cmd = ["efibootmgr","--bootorder",",".join(order)]
    if dry_run:
        return "DRY_RUN: " + " ".join(cmd)
    return run(cmd, check=False).stdout

def mint_receipt(manifest_path: pathlib.Path, manifest_sha: str, created_bootnum: str, label: str, loader: str, disk: str, part: int) -> None:
    ctl = pathlib.Path("/usr/local/sbin/aevum_receiptctl.py")
    if not ctl.exists():
        print("WARN: missing aevum_receiptctl.py; skipping receipt mint", file=sys.stderr)
        return
    kv = [
        "component=boot",
        "boot_action=uki_bootentry_create",
        f"boot_manifest_path={str(manifest_path)}",
        f"boot_manifest_sha256=sha256:{manifest_sha}",
        f"boot_disk={disk}",
        f"boot_part={part}",
        f"boot_label={label[:64]}",
        f"boot_loader={loader[:128]}",
    ]
    if created_bootnum:
        kv.append(f"boot_created_bootnum={created_bootnum}")
    msg = f"UKI boot entry created: {created_bootnum or 'unknown'}"
    subprocess.run([sys.executable, str(ctl), "note", msg] + kv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--uki", default="", help="Path to UKI .efi (default: newest in /boot/efi/EFI/Linux)")
    ap.add_argument("--label", default="", help="EFI boot entry label (default derived from UKI filename)")
    ap.add_argument("--set-bootnext", action="store_true", help="Set BootNext to the created entry (one-time boot)")
    ap.add_argument("--set-first", action="store_true", help="Prepend created entry to BootOrder")
    ap.add_argument("--dry-run", action="store_true", help="Print actions, do not change EFI variables")
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("Run as root (sudo).", file=sys.stderr)
        return 2

    uki = pathlib.Path(args.uki) if args.uki else find_latest_uki()
    if not uki.exists():
        raise FileNotFoundError(str(uki))

    partdev = esp_source()
    disk, part = disk_and_part(partdev)
    loader = efi_loader_path(uki)
    label = args.label or f"Aevum UKI {uki.name[:32]}"
    ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

    outdir = pathlib.Path("/var/lib/aevum/workstation/boot/efi")
    artdir = outdir / "artifacts"
    outdir.mkdir(parents=True, exist_ok=True)
    artdir.mkdir(parents=True, exist_ok=True)

    before = run(["efibootmgr","-v"], check=False).stdout
    before_path = artdir / f"efibootmgr_before_{ts}.txt"
    before_path.write_text(before, encoding="utf-8")
    before_sha = sha256_file(before_path)

    bootnum, create_out = create_boot_entry(disk, part, label, loader, args.dry_run)
    create_path = artdir / f"efibootmgr_create_{ts}.txt"
    create_path.write_text(create_out, encoding="utf-8")
    create_sha = sha256_file(create_path)

    # If efibootmgr didn't echo BootXXXX, infer via diff
    after = run(["efibootmgr","-v"], check=False).stdout
    after_path = artdir / f"efibootmgr_after_{ts}.txt"
    after_path.write_text(after, encoding="utf-8")
    after_sha = sha256_file(after_path)

    if not bootnum and not args.dry_run:
        before_set = set(re.findall(r"Boot([0-9A-Fa-f]{4})\*", before))
        after_set = set(re.findall(r"Boot([0-9A-Fa-f]{4})\*", after))
        diff = list(after_set - before_set)
        bootnum = diff[0].upper() if diff else None

    before_order = parse_bootorder(before)
    order_action_out = ""
    bootnext_out = ""

    if bootnum and args.set_first:
        order_action_out = set_bootorder_first(bootnum, before_order, args.dry_run)

    if bootnum and args.set_bootnext:
        bootnext_out = set_bootnext(bootnum, args.dry_run)

    # recompute after if we changed variables
    if (args.set_first or args.set_bootnext) and not args.dry_run:
        after2 = run(["efibootmgr","-v"], check=False).stdout
        after = after2
        after_path.write_text(after, encoding="utf-8")
        after_sha = sha256_file(after_path)

    uki_sha = sha256_file(uki)

    manifest = {
        "type": "aevum_uki_bootentry_change_v1",
        "ts_utc": utc_now(),
        "esp_source": partdev,
        "esp_disk": disk,
        "esp_part": part,
        "uki_path": str(uki),
        "uki_sha256": "sha256:" + uki_sha,
        "efi_loader": loader,
        "label": label,
        "dry_run": bool(args.dry_run),
        "created_bootnum": bootnum or "",
        "bootnext_set": bool(args.set_bootnext),
        "set_first": bool(args.set_first),
        "efibootmgr_before_path": str(before_path),
        "efibootmgr_before_sha256": "sha256:" + before_sha,
        "efibootmgr_create_path": str(create_path),
        "efibootmgr_create_sha256": "sha256:" + create_sha,
        "efibootmgr_after_path": str(after_path),
        "efibootmgr_after_sha256": "sha256:" + after_sha,
        "order_action_output_sha256": "sha256:" + sha256_text(order_action_out) if order_action_out else "",
        "bootnext_output_sha256": "sha256:" + sha256_text(bootnext_out) if bootnext_out else "",
    }

    manifest_path = outdir / f"bootentry_change_{ts}.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest_sha = sha256_file(manifest_path)

    # Mint receipt (registry binding injected by receiptctl)
    mint_receipt(manifest_path, manifest_sha, bootnum or "", label, loader, disk, part)

    print(json.dumps({"ok": True, "created_bootnum": bootnum or "", "manifest_path": str(manifest_path), "manifest_sha256": "sha256:"+manifest_sha}, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
