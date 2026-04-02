#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List


def load_chain(chain_path: Path) -> List[Dict[str, Any]]:
    if not chain_path.exists():
        raise FileNotFoundError(f"Chain file not found: {chain_path}")
    events: List[Dict[str, Any]] = []
    with chain_path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on line {line_no} of {chain_path}") from exc
    if not events:
        raise ValueError(f"Chain is empty: {chain_path}")
    return events


def save_chain(chain_path: Path, events: List[Dict[str, Any]]) -> None:
    chain_path.parent.mkdir(parents=True, exist_ok=True)
    with chain_path.open("w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event, sort_keys=True) + "\n")


def copy_chain(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)


def tamper_event(events: List[Dict[str, Any]], index: int, field: str, new_value: str) -> None:
    if index < 0 or index >= len(events):
        raise IndexError(f"Event index {index} out of range (0..{len(events)-1})")
    if field not in events[index]:
        raise KeyError(f"Field '{field}' not found in event index {index}")
    try:
        parsed_value = json.loads(new_value)
    except json.JSONDecodeError:
        parsed_value = new_value
    events[index][field] = parsed_value


def delete_event(events: List[Dict[str, Any]], index: int) -> None:
    if index < 0 or index >= len(events):
        raise IndexError(f"Event index {index} out of range (0..{len(events)-1})")
    del events[index]


def fork_chain(events: List[Dict[str, Any]], index: int, identity_dir: Path | None) -> None:
    if index <= 0 or index >= len(events):
        raise IndexError(f"Fork index {index} must be between 1 and {len(events)-1}")
    if identity_dir is None:
        raise ValueError("fork mode requires --identity-dir")

    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root / "src"))
    from aevum_rrp.common import load_private_key, aeo_id_from_event, sign_event

    base = dict(events[index])
    base["payload"] = {"message": "forked branch"}
    base["event_hash"] = "0" * 64
    base["event_hash"] = __import__("hashlib").sha256(json.dumps(base["payload"], sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    base["aeo_id"] = aeo_id_from_event(base)
    sk = load_private_key(identity_dir / "device_ed25519_sk.pem")
    base["signature"] = sign_event(sk, base)
    events.append(base)


def main() -> None:
    parser = argparse.ArgumentParser(description="Create tampered/forked/gapped copies of an RRP chain.")
    parser.add_argument("--chain", required=True, help="Path to the source chain jsonl file.")
    parser.add_argument("--out", required=True, help="Path to write the modified chain jsonl file.")
    subparsers = parser.add_subparsers(dest="mode", required=True)

    tamper_parser = subparsers.add_parser("tamper", help="Modify one field in one event.")
    tamper_parser.add_argument("--index", type=int, required=True, help="Zero-based event index.")
    tamper_parser.add_argument("--field", required=True, help="Top-level field to modify.")
    tamper_parser.add_argument("--value", required=True, help="Replacement value. JSON allowed, otherwise treated as string.")

    gap_parser = subparsers.add_parser("gap", help="Delete one event to create a gap.")
    gap_parser.add_argument("--index", type=int, required=True, help="Zero-based event index.")

    fork_parser = subparsers.add_parser("fork", help="Insert a forked event.")
    fork_parser.add_argument("--index", type=int, required=True, help="Zero-based event index to fork from.")
    fork_parser.add_argument("--identity-dir", required=False, help="Identity dir containing signing key for valid fork creation.")

    args = parser.parse_args()
    src = Path(args.chain).resolve()
    out = Path(args.out).resolve()
    copy_chain(src, out)
    events = load_chain(out)

    if args.mode == "tamper":
        tamper_event(events, args.index, args.field, args.value)
    elif args.mode == "gap":
        delete_event(events, args.index)
    elif args.mode == "fork":
        fork_chain(events, args.index, Path(args.identity_dir).resolve() if args.identity_dir else None)
    else:
        raise ValueError(f"Unsupported mode: {args.mode}")

    save_chain(out, events)
    print(f"Wrote modified chain: {out}")


if __name__ == "__main__":
    main()
