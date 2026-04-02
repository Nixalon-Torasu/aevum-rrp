#!/usr/bin/env python3
"""
aevum_firewall.py (v0.2)

nftables firewall with "install" vs "locked" modes.

Goals
- Default-deny posture (input/output policy drop).
- SSH-safe by default for LAN/RFC1918 so remote operators don't brick the box.
- Install mode allows the minimum outbound needed for provisioning (DNS/NTP/HTTP/HTTPS).
- Locked mode denies new outbound by default (keeps DHCP so the NIC doesn't silently die).
- Drop logs are rate-limited and prefixed for later receipting.

Modes
- install: allow DNS/NTP/HTTP/HTTPS outbound for provisioning; inbound still default-deny (LAN SSH allowed)
- locked : deny outbound except established/loopback + DHCP; inbound default-deny (LAN SSH allowed)

Log prefixes (journald/kernel):
- AEVUM_NFT IN_DROP
- AEVUM_NFT OUT_DROP

This script can:
- --print : print ruleset to stdout
- --apply : apply ruleset using `nft -f -`
- --set-mode install|locked : persist mode to /etc/aevum/firewall_mode
"""

from __future__ import annotations
import argparse
import os
import pathlib
import subprocess
import shutil
import sys

MODE_PATH = pathlib.Path("/etc/aevum/firewall_mode")
SSH_ALLOW_CIDRS_PATH = pathlib.Path("/etc/aevum/ssh_allow_cidrs")

DEFAULT_SSH_ALLOW_CIDRS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
]

RULESET_TEMPLATE = r"""
flush ruleset

table inet filter {{
  chain input {{
    type filter hook input priority 0;
    policy drop;

    iif lo accept
    ct state established,related accept

    # Allow ICMP (diagnostics)
    ip protocol icmp accept
    ip6 nexthdr icmpv6 accept

    {in_allow}

    # SSH allow (from /etc/aevum/ssh_allow_cidrs; defaults to RFC1918 if missing)
    {ssh_allow}

    # Log and drop everything else (rate-limited)
    limit rate 10/second log prefix "AEVUM_NFT IN_DROP " flags all counter drop
  }}

  chain forward {{
    type filter hook forward priority 0;
    policy drop;
  }}

  chain output {{
    type filter hook output priority 0;
    policy drop;

    oif lo accept
    ct state established,related accept

    {out_allow}

    # Log and drop everything else (rate-limited)
    limit rate 10/second log prefix "AEVUM_NFT OUT_DROP " flags all counter drop
  }}
}}
"""

# Always-needed allowances (keep NIC alive)
IN_BASE = r"""
    # DHCPv4 replies (server:67 -> client:68)
    udp sport 67 udp dport 68 accept
    # DHCPv6 replies (server:547 -> client:546)
    udp sport 547 udp dport 546 accept
"""

OUT_BASE = r"""
    # DHCPv4 requests (client:68 -> server:67)
    udp sport 68 udp dport 67 accept
    # DHCPv6 requests (client:546 -> server:547)
    udp sport 546 udp dport 547 accept
"""

OUT_INSTALL = r"""
    # Install/provisioning mode outbound (minimum viable)
    udp dport 53 accept         # DNS (UDP)
    tcp dport 53 accept         # DNS (TCP)
    udp dport 123 accept        # NTP
    tcp dport {80,443} accept   # HTTP/HTTPS
"""

OUT_LOCKED = r"""
    # Locked mode outbound: nothing new leaves by default.
"""

def read_lines(path: pathlib.Path) -> list[str]:
    try:
        raw = path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return []
    out: list[str] = []
    for ln in raw:
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        out.append(ln)
    return out

def ssh_allow_rules() -> str:
    cidrs = read_lines(SSH_ALLOW_CIDRS_PATH) or DEFAULT_SSH_ALLOW_CIDRS
    rules: list[str] = []
    for c in cidrs:
        if ":" in c:
            rules.append(f"ip6 saddr {c} tcp dport 22 accept")
        else:
            rules.append(f"ip saddr {c} tcp dport 22 accept")
    if not rules:
        # Should never happen, but keep a commented hint
        return "\n    # ip saddr 192.168.0.0/16 tcp dport 22 accept\n"
    extra=current_ssh_remote_rules()
    return "\n    " + "\n    ".join(rules) + "\n" + (("    "+extra) if extra else "")


def current_ssh_remote_rules() -> str:
    """If we're currently connected over SSH, allow the remote IP explicitly (safety belt)."""
    sc = os.environ.get("SSH_CONNECTION","").strip()
    if not sc:
        return ""
    parts = sc.split()
    if not parts:
        return ""
    rip = parts[0].strip()
    if not rip:
        return ""
    # Don't try to validate deeply; nft will reject nonsense.
    if ":" in rip:
        return f"ip6 saddr {rip} tcp dport 22 accept\n"
    return f"ip saddr {rip} tcp dport 22 accept\n"


def read_mode() -> str:
    """Return persisted mode; default is install (safe for first boot)."""
    try:
        m = MODE_PATH.read_text(encoding="utf-8").strip().lower()
        return m if m in ("install", "locked") else "install"
    except Exception:
        return "install"

def write_mode(mode: str) -> None:
    MODE_PATH.parent.mkdir(parents=True, exist_ok=True)
    MODE_PATH.write_text(mode + "\n", encoding="utf-8")
    try:
        os.chmod(MODE_PATH, 0o644)
    except Exception:
        pass

def build_ruleset(mode: str) -> str:
    out_allow = OUT_BASE + (OUT_INSTALL if mode == "install" else OUT_LOCKED)
    return RULESET_TEMPLATE.format(out_allow=out_allow, in_allow=IN_BASE, ssh_allow=ssh_allow_rules())

def apply_ruleset(rules: str) -> int:
    if shutil.which("nft") is None:
        print("FAIL: nft not found (install nftables)", file=sys.stderr)
        return 127
    cp = subprocess.run(["nft", "-f", "-"], input=rules, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if cp.returncode != 0:
        print(cp.stderr.strip(), file=sys.stderr)
    return cp.returncode

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", default="", choices=["","install","locked"], help="Override mode (otherwise read /etc/aevum/firewall_mode).")
    ap.add_argument("--set-mode", default="", choices=["install","locked"], help="Persist firewall mode.")
    ap.add_argument("--print", action="store_true", help="Print ruleset.")
    ap.add_argument("--apply", action="store_true", help="Apply ruleset with nft.")
    args = ap.parse_args()

    if args.set_mode:
        write_mode(args.set_mode)

    mode = args.mode or read_mode()
    rules = build_ruleset(mode)

    if args.print or (not args.apply):
        print(rules)

    if args.apply:
        return apply_ruleset(rules)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())