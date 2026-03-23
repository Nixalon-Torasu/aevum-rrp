#!/usr/bin/env python3
from __future__ import annotations

"""aevum_firewallctl.py

Operator control surface for Aevum firewall modes + short-lived egress windows.

Modes:
  - locked  : default-deny egress
  - install : provisioning egress baseline

This tool is intentionally small and dependency-light. It:
  1) Writes /etc/aevum/firewall_mode
  2) Applies immediately via /usr/local/sbin/aevum_firewall.py --apply (best-effort)

It also provides bounded egress windows by switching to install mode temporarily
and then restoring the previous mode.

Exit codes:
  0 success
  2 usage / argument errors
  3 apply failure
"""

import argparse
import os
import pathlib
import subprocess
import sys
import time
from typing import List

MODE_PATH = pathlib.Path("/etc/aevum/firewall_mode")
FIREWALL_APPLY = pathlib.Path("/usr/local/sbin/aevum_firewall.py")

def _read_mode() -> str:
    try:
        m = MODE_PATH.read_text(encoding="utf-8").strip()
        return m if m in ("install","locked") else "locked"
    except FileNotFoundError:
        return "locked"

def _write_mode(mode: str) -> None:
    MODE_PATH.parent.mkdir(parents=True, exist_ok=True)
    MODE_PATH.write_text(mode + "\n", encoding="utf-8")

def _apply() -> None:
    if not FIREWALL_APPLY.exists():
        # If the apply tool isn't present yet, this is a staging environment.
        return
    p = subprocess.run([str(FIREWALL_APPLY), "--apply"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if p.returncode != 0:
        raise RuntimeError((p.stderr or p.stdout or "apply failed").strip())

def cmd_set(mode: str) -> int:
    if mode not in ("install","locked"):
        print("FAIL: mode must be 'install' or 'locked'", file=sys.stderr)
        return 2
    _write_mode(mode)
    try:
        _apply()
    except Exception as e:
        print(f"FAIL: apply failed: {e}", file=sys.stderr)
        return 3
    print(f"OK: firewall_mode={mode}")
    return 0

def cmd_status() -> int:
    mode = _read_mode()
    print(f"firewall_mode={mode}")
    return 0

def cmd_print() -> int:
    # Print rendered ruleset for the current mode (best-effort)
    fw = FIREWALL_APPLY
    if fw.exists():
        subprocess.run([str(fw), "--print"], check=False)
        return 0
    print("WARN: /usr/local/sbin/aevum_firewall.py not present; nothing to print", file=sys.stderr)
    return 0

def cmd_egress_window(seconds: int, argv: List[str], profile: str | None = None) -> int:
    if seconds <= 0:
        print("FAIL: seconds must be > 0", file=sys.stderr)
        return 2
    if not argv:
        print("FAIL: command missing", file=sys.stderr)
        return 2

    prev = _read_mode()
    # If profile is provided, write a runtime overlay used by aevum_firewall.py (if supported).
    # For now, profiles are handled by aevum-egressctl; firewallctl only toggles install/locked.
    try:
        _write_mode("install")
        _apply()
    except Exception as e:
        print(f"FAIL: could not enter install mode: {e}", file=sys.stderr)
        return 3

    start = time.time()
    rc = 0
    try:
        # Run command with a hard wall-clock timeout.
        p = subprocess.run(argv, timeout=seconds)
        rc = int(p.returncode)
    except subprocess.TimeoutExpired:
        rc = 124
        print(f"FAIL: egress window timed out after {seconds}s", file=sys.stderr)
    finally:
        try:
            _write_mode(prev)
            _apply()
        except Exception as e:
            # Do not hide original rc, but report restoration failure loudly.
            print(f"FAIL: could not restore firewall mode to '{prev}': {e}", file=sys.stderr)
            if rc == 0:
                rc = 3

    dur = int(time.time() - start)
    print(f"egress_window_seconds={seconds} elapsed_seconds={dur} rc={rc} restored_mode={prev}")
    return rc

def main() -> int:
    ap = argparse.ArgumentParser(prog="aevum-firewallctl")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("status", help="Print current firewall mode").set_defaults(fn=lambda a: cmd_status())
    sub.add_parser("print", help="Print ruleset for current mode (best-effort)").set_defaults(fn=lambda a: cmd_print())

    p_locked = sub.add_parser("locked", help="Set firewall mode to locked and apply")
    p_locked.set_defaults(fn=lambda a: cmd_set("locked"))

    p_install = sub.add_parser("install", help="Set firewall mode to install and apply")
    p_install.set_defaults(fn=lambda a: cmd_set("install"))

    p_run = sub.add_parser("egress-run", help="Temporarily open egress (install mode) for N seconds and run command")
    p_run.add_argument("seconds", type=int)
    p_run.add_argument("--", dest="sep", action="store_true")
    p_run.add_argument("cmd_argv", nargs=argparse.REMAINDER)
    p_run.set_defaults(fn=lambda a: cmd_egress_window(a.seconds, a.cmd_argv))

    args = ap.parse_args()
    # argparse.REMAINDER keeps leading '--' sometimes; strip it.
    if hasattr(args, "cmd_argv") and args.cmd_argv and args.cmd_argv[0] == "--":
        args.cmd_argv = args.cmd_argv[1:]
    return int(args.fn(args))

if __name__ == "__main__":
    raise SystemExit(main())
