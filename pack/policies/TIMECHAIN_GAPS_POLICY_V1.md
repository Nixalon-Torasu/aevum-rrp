AEVUM:POLICY:TIMECHAIN_GAPS:V1

Requirement
- Missing TimeBlocks MUST be explicitly represented. Silent holes are forbidden.

Representation modes (Year-1)
1) Per-second placeholders (preferred for short gaps)
- Emit TimeBlockPayload (TBV0) with flags including:
  - GAP_PLACEHOLDER
  - WALLCLOCK_ESTIMATED
- time_block_id increments per missing second.

2) Coalesced gap summary (permitted for large gaps)
- Emit TimeGapSummaryPayload (TGSv1) with:
  - gap_start_time_block_id
  - gap_end_time_block_id
  - gap_count
- The producer may advance last_time_block_id to gap_end without emitting every per-second placeholder.

Verifier posture
- Verifier MUST accept both representations as valid.
- Verifier MAY warn if coalesced gaps exceed an operator-configured threshold.

Non-blocking
- Gap receipts exist so the system can continue even when receipt printing was temporarily unavailable.
