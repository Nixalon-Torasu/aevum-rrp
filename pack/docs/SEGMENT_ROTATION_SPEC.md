# Segment Rotation Spec (Workstation Boundary)

**Goal:** Keep receipt verification cost bounded without changing any envelope bytes.

Segment rotation is **file management**. It MUST NOT:
- change event envelopes
- reinterpret semantics
- block producers (best-effort)

## Deterministic policy modes

### hourly_timeblock (default)
- Use TimeChain `last_time_block_id` as the canonical tick counter.
- Compute `cutoff = floor(now_tb / window_seconds) * window_seconds - 1`.
- Segment each chain by moving all valid lines with `time_block_id <= cutoff` into a closed segment file.
- Keep the remaining lines in the active file.

This yields stable, reproducible segments aligned to the canonical time backbone.

## Files

Active:
- `<base>/accurate/receipts/<CHAIN>.jsonl`

Segments:
- `<base>/accurate/segments/<CHAIN>/seg_<INDEX>_tb_<first>_<last>__seq_<first>_<last>.jsonl`

Manifests:
- `<base>/accurate/segments/<CHAIN>/manifest_<INDEX>_tb_<first>_<last>__seq_<first>_<last>.json`

Manifests chain forward via `prev_manifest_sha256`.

## Replay order

Verifier and receipt CLI must treat:
`(segments in manifest order) + (active file)`

