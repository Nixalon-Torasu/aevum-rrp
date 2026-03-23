from __future__ import annotations

import argparse
import json
from pathlib import Path

from .common import (
    append_jsonl,
    build_event,
    collect_pcr_snapshot,
    device_id_from_public_key,
    ensure_dirs,
    load_private_key,
    load_public_key,
    public_key_b64,
    read_last_aeo,
    sign_event,
)


def main() -> int:
    ap = argparse.ArgumentParser(description="Emit an RRP AEO into the local chain")
    ap.add_argument("--state-dir", required=True)
    ap.add_argument("--identity-dir", required=True)
    ap.add_argument("--event-type", required=True)
    ap.add_argument("--input-class", required=True)
    ap.add_argument("--payload-json", required=True)
    ap.add_argument("--pcr-provider", default="mock")
    args = ap.parse_args()

    state_dir = Path(args.state_dir)
    identity_dir = Path(args.identity_dir)
    chain_dir, _, _ = ensure_dirs(state_dir)
    chain_path = chain_dir / "aeo_chain.jsonl"

    payload = json.loads(args.payload_json)
    sk = load_private_key(identity_dir / "device_ed25519_sk.pem")
    pk = load_public_key(identity_dir / "device_ed25519_pk.pem")
    previous = read_last_aeo(chain_path)
    event = build_event(
        previous=previous,
        device_id=device_id_from_public_key(pk),
        device_pubkey=public_key_b64(pk),
        event_type=args.event_type,
        input_class=args.input_class,
        payload=payload,
        pcr_snapshot=collect_pcr_snapshot(args.pcr_provider),
    )
    event["signature"] = sign_event(sk, event)
    append_jsonl(chain_path, event)
    print(event["aeo_id"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
