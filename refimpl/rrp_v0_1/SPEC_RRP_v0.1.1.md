# AEVUM RRP v0.1.1
**Receipt Request Protocol — Minimal Cryptographic Provenance Core**

## 0. Scope

RRP v0.1.1 defines a protocol for producing and verifying a cryptographically verifiable, device-bound, continuous chain of machine-observed events.

### Guarantees

- Event lineage integrity
- Device-bound authorship (Ed25519)
- Explicit continuity (no silent gaps)
- Detectable forks

### Non-Goals

RRP v0.1.1 does **not** guarantee truth or correctness of events, trustworthy inputs, resistance to full system compromise, secure time, or hardware attestation.

## 1. Core Object — AEO

```json
{
  "aeo_id": "hex_sha256",
  "prev_aeo_id": "hex_sha256 | null",
  "sequence": 123,
  "timestamp": 1700000000,
  "pcr_snapshot": {"provider": "mock", "selection": "sha256:0,1,...", "composite_hash": "hex", "raw": {}},
  "device_id": "hex_sha256",
  "device_pubkey": "base64_ed25519",
  "event_type": "SYSTEM | USER_INPUT | APPLICATION | EXTERNAL | HEARTBEAT | KEY_ROTATION",
  "input_class": "SYSTEM | USER_INPUT | APPLICATION | EXTERNAL",
  "event_hash": "hex_sha256",
  "payload": {},
  "signature": "base64_ed25519",
  "schema_version": "AEO-RRP-v0.1.1"
}
```

## 2. Canonical Encoding

All hashing and signing MUST use deterministic encoding over the event object excluding `signature`:

```text
json.dumps(event_without_signature, sort_keys=True, separators=(",", ":"))
```

## 3. AEO ID

```text
aeo_id = sha256(canonical_event_bytes)
```

## 4. Signature Model

- Algorithm: Ed25519
- Signature MUST cover canonical event bytes excluding `signature`
- `device_id` MUST equal `sha256(device_pubkey_raw_bytes)`

Verifiers MUST validate both signature correctness and `device_id` consistency.

## 5. Chain Structure

### 5.1 Linking

```text
prev_aeo_id(n) == aeo_id(n-1)
```

### 5.2 Sequence

```text
sequence(n+1) = sequence(n) + 1
```

No gaps allowed.

### 5.3 Genesis Event

The first event MUST have `prev_aeo_id = null`.

## 6. Input Classification

- `SYSTEM`
- `USER_INPUT`
- `APPLICATION`
- `EXTERNAL`

## 7. Heartbeat Rule

If no events occur within an implementation-defined interval, the emitter SHOULD emit a `HEARTBEAT` event using `input_class = SYSTEM`.

## 8. Time Model

`timestamp` is informational only in v0.1.1 and SHOULD be monotonic.

## 9. Verifier Semantics (Normative)

A verifier MUST return exactly one terminal result:

- `VALID`
- `INVALID`
- `GAP_DETECTED`
- `FORK_DETECTED`

### 9.1 Evaluation Order

1. Structural validity
2. Cryptographic integrity
3. Fork detection
4. Sequence continuity
5. Link integrity
6. Otherwise `VALID`

### 9.2 Outcome Definitions

- `VALID`: chain is internally consistent and continuous
- `INVALID`: structural, hash, signature, or identity violation
- `GAP_DETECTED`: sequence discontinuity
- `FORK_DETECTED`: competing lineage detected

### 9.3 Recommended Exit Codes

- `0 = VALID`
- `1 = INVALID`
- `2 = GAP_DETECTED`
- `3 = FORK_DETECTED`

## 10. Security Model

Guaranteed:
- Events cannot be modified without detection
- Chain cannot be altered silently without verification failure
- Device authorship is cryptographically provable

Not guaranteed:
- Event truthfulness
- Protection from compromised host
- Protection from malicious inputs

## 11. Minimal Implementation Requirements

A conforming implementation MUST include:
- AEO generator
- append-only local chain storage
- Ed25519 keypair generation
- strict verifier

## 12. Known Limitations

- No TPM attestation
- No rollback resistance
- No external anchoring
- No privacy layer
- No zero-knowledge proofs

## 13. Forward Roadmap

v0.2 targets: TPM quote integration, anti-rollback, external anchoring, and runtime state binding.

## Final Positioning Statement

RRP v0.1.1 provides a cryptographically verifiable chain of device-bound events with enforced continuity and explicit provenance. It proves how events were recorded and linked—not that they are true.


## v0.1.2 Verification Clarification

Verifiers MUST recompute `event_hash` from the canonical `payload` and reject mismatches as `INVALID`.
