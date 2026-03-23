Aevum Verifier v0.1 (Year-1)

What this verifies
- JSONL logs under /var/lib/aevum/receipts/
- Hash chaining via prev_event_hash (tamper evidence)
- event_hash recomputation using canonical JSON hashing of the unsigned envelope fields
- Ed25519 signature over the raw 32-byte event_hash

Spec alignment
- EventEnvelope fields and signature posture are defined in the Aevum Core Spec:
  - EventEnvelope fields include: chain_id, subject_id, seq_no, time_block_id, local_monotime, capture_device, prev_event_hash, payload_hash, event_hash, signature.
  - Signature is over event_hash.
- Payload retention is optional: payloads may be pruned later without breaking envelope integrity. Payload verification is optional.

Files
- aevum_verify.py
- schemas/identity.schema.json
- schemas/event_envelope.schema.json

Install
- sudo python3 -m pip install cryptography

Usage (hash-chain + event_hash + signature):
- Verify TimeChain:
  sudo ./aevum_verify.py --base /var/lib/aevum --chain T --identity /var/lib/aevum/identity/identity.public.json

- Verify Interaction chain:
  sudo ./aevum_verify.py --base /var/lib/aevum --chain I --identity /var/lib/aevum/identity/identity.public.json

Optional payload checking:
  sudo ./aevum_verify.py --base /var/lib/aevum --chain I --identity /var/lib/aevum/identity/identity.public.json --check-payloads

Note
- canon_digest is intentionally OPTIONAL and MUST NOT be required for access or basic function.
