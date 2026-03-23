AEVUM:WIRE:EVENT_HASH_CANON:V1 (Frozen)

Source alignment: Aevum Spec 1 EventEnvelope
- chain_id        : uint8
- subject_id      : bytes32
- seq_no          : uint64
- time_block_id   : uint64
- local_monotime  : int64
- capture_device  : bytes16
- prev_event_hash : bytes32 (sha256)
- payload_hash    : bytes32 (sha256)

Canonical computation (big-endian integers):
event_hash = SHA256( chain_id(u8) ||
                     subject_id(32B) ||
                     seq_no(u64) ||
                     time_block_id(u64) ||
                     local_monotime(i64) ||
                     capture_device(16B) ||
                     prev_event_hash(32B) ||
                     payload_hash(32B) )

Signature scope:
signature = Ed25519_sign( SK_chain, event_hash_bytes32 )

Notes:
- Fixed-length concat => no delimiter ambiguity.
- V1 legacy JSON hashing still supported in verifier for backwards compatibility.
