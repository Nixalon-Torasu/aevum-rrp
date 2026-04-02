from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from .emit import main as emit_main


def main() -> int:
    ap = argparse.ArgumentParser(description="Emit HEARTBEAT events on an interval")
    ap.add_argument("--state-dir", required=True)
    ap.add_argument("--identity-dir", required=True)
    ap.add_argument("--interval-seconds", type=int, default=5)
    ap.add_argument("--count", type=int, default=3)
    args = ap.parse_args()

    for i in range(args.count):
        import sys
        sys.argv = [
            "emit",
            "--state-dir", args.state_dir,
            "--identity-dir", args.identity_dir,
            "--event-type", "HEARTBEAT",
            "--input-class", "SYSTEM",
            "--payload-json", json.dumps({"heartbeat_index": i + 1}),
        ]
        emit_main()
        if i < args.count - 1:
            time.sleep(args.interval_seconds)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
