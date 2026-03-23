AEVUM:WIRE:PAYLOAD_HASH_CANON:V1 (Frozen for Year-1 JSON payloads)

Spec alignment: Aevum Spec 1 payload_hash is "hash of payload bytes". Payloads are versioned.

Year-1 rule (this bootstrap pack):
1) payload_bytes = UTF-8 JSON, canonicalized as:
   - sort_keys=True
   - separators=(",", ":")
   - ensure_ascii=False
   - no trailing newline in the hashed bytes
2) payload_hash = SHA256(payload_bytes)

Storage:
- Payload files are written as payload_bytes + "\n" for human friendliness.
- The hash is computed on payload_bytes only (newline excluded).
