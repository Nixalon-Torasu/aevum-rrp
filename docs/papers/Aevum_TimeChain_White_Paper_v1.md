# Aevum TimeChain White Paper
**Subtitle:** Drift-Resilient Time Integrity for Single-Node Provenance: Bounded UTC, Pinned Witnesses, and Fail-Closed Recovery  
**Version:** 1.0  
**Date:** 2026-01-23  
**Document type:** White Paper (technical + product-oriented)  
**Scope:** Local Single-Node STRICT (implementation-grade spec available separately)

---

## Executive Summary
Most provenance, audit, and “proof of activity” systems are quietly broken at the same point: **time**. They assume wall-clock timestamps are authoritative and stable. In reality, wall clocks drift, get stepped, get spoofed, and—under adversarial pressure—get rewritten. Even without an attacker, offline operation turns “exact time” into a fiction.

**Aevum TimeChain** takes an uncompromising stance: **time is evidence, not truth**. It builds a 1-second append-only time spine that:
- establishes **total order** using a monotonic clock,
- represents UTC only as **bounded intervals** (uncertainty-aware),
- uses **pinned witness evidence** (NTS-NTP/Roughtime/GNSS) without trusting any witness as infallible,
- commits per-second Merkle roots for all other Aevum chains, and
- enforces **fail-closed** behavior: integrity violations trigger deterministic **LOCKDOWN** and require explicit **recovery receipts** (“no silent recovery”).

The result is a time substrate that is drift-resistant, rollback-hostile, oracle-poisoning-resistant, and exportable with coercion-resistant time bucketing.

---

## Why Time Integrity Fails in Practice
### The common failure pattern
Most systems do some version of:
1) read wall-clock time,
2) stamp events with that time,
3) maybe sync occasionally,
4) hope for the best.

This fails under:
- **Clock spoofing:** attackers force the system clock to lie (NTP spoofing, DNS tricks, compromised time sources).
- **Clock stepping:** OS corrections move time backward/forward, silently destroying event order.
- **Offline drift:** a disconnected device accumulates uncertainty; reconnect “snap” hides the truth.
- **Rollback:** restoring a snapshot replays old timestamps as if they were current.
- **Coercive leakage:** high-resolution timestamps expose sensitive patterns even when content is encrypted.

### The core mistake
Wall-clock time is treated as **authority** when it can only be treated as **evidence**.

---

## The Aevum TimeChain Approach (in one page)
TimeChain is built on five principles:

1) **Order before time**  
   A monotonic clock determines ordering. If ordering is wrong, everything is wrong.

2) **UTC as bounds, not points**  
   Every tick publishes `[t_min_utc, t_max_utc]` instead of a single “timestamp”.

3) **Pinned witnesses, not trusted witnesses**  
   Witnesses are admissible only if pinned (identity+key). Rotation is governed and explicit.

4) **Determinism everywhere**  
   Canonical encoding, hashing, signing inputs, Merkle construction, and enums are pinned. No “interpretation drift.”

5) **Cruel by policy**  
   Integrity violations map to deterministic actions. If you wrong it, it does not “smooth it over”—it **LOCKDOWNs**.

---

## Architecture Overview
### 1-second tick spine
Each second, the producer emits a **TimeChainTick** that commits:
- monotonic interval (start/end),
- UTC bounds,
- quality state (SYNCED/HOLDOVER/OFFLINE/ANOMALOUS),
- per-chain Merkle roots (P/R/Φ/I…),
- references to evidence receipts (witness set, attestation, counter, anomalies),
- and a hash-chain link to the prior tick.

**Illustration (conceptual):**
```
Tick(t-1) --hash--> Tick(t) --hash--> Tick(t+1) ...
    |                 |                 |
  roots(P,R,Φ,I)    roots(P,R,Φ,I)    roots(P,R,Φ,I)
    |                 |                 |
  evidence refs      evidence refs      evidence refs
```

### Evidence receipts (append-only)
Evidence is recorded as independent receipts referenced by ticks:
- TimeWitnessSampleSet (witness intervals)
- TimeAttestation (posture bind to policy digests)
- MonotonicCounterReceipt (anti-rollback)
- ClockAnomaly (declared seams and lies)
- TimeReconcile (optional bounded fitting over a window)

---

## Key Features (what makes it “nasty”)
### 1) Total-order guarantee under adversarial time
Ticks are ordered by monotonic time and an increasing `time_block_id`. UTC cannot reorder events because it is never used as the ordering primitive.

### 2) Honest degradation
When witnesses disappear:
- TimeChain does **not** pretend time is still precise.
- UTC bounds widen deterministically via integer-only math.
- Quality state degrades (SYNCED → HOLDOVER → OFFLINE).
- Any attempt to claim SYNCED without evidence triggers a failure.

### 3) Oracle poisoning resistance
- Only pinned witnesses are admissible.
- Witness sets must match the active pinset digest.
- Rotation is append-only governance, STRICT default = **no overlap**.
- Quorum and skew rules are enforced; violation produces anomalies or rejection.

### 4) Rollback hostility
Rollback is addressed by monotonic counters:
- If counter evidence is required and non-monotonic, that is not “a warning.”
- It is a hard integrity event and triggers deterministic LOCKDOWN.

### 5) Cruel failure semantics (TripwirePolicy)
Failures map to deterministic actions:
- hashchain break, fork detection, counter non-monotonic, pinset mismatch → **LOCKDOWN**
- LOCKDOWN seals the vault; the chain is non-authoritative until recovery ritual receipts exist.

### 6) No silent recovery
To return to “green,” the system must publish:
- ManualUnsealReceipt (operator acknowledgment),
- fresh counter and attestation,
- fork resolution (if applicable),
- key rotation with roll-forward proof,
- RecoveryEpochGenesis (explicit scar seam),
- then resume ticks in a new epoch.

### 7) Coercion-resistant export
Public exports:
- bucket time coarsely (default 15 min; policy-tunable),
- omit witness endpoints and monotime,
- export digests + bounded reason codes (structure over content).

---

## Threat Model (practical)
**Attacker capabilities:**
- manipulate system clock,
- spoof time witnesses,
- modify stored files,
- snapshot/restore disk state,
- attempt silent key changes.

**TimeChain mitigations:**
- monotonic order + hash chaining + signatures (tamper evidence),
- pinned witnesses + quorum/skew rules (oracle resistance),
- monotonic counter receipts (rollback detection),
- bounded reason codes + deterministic tripwires (fail-closed),
- recovery ritual receipts (no silent fix).

**Residual risks:**
- If hardware has no reliable monotonic source and no secure counter, rollback detection weakens (still tamper-evident, less rollback-hostile).
- If witness ecosystem is unavailable for long periods, UTC bounds become wide (by design).
- Physical attacks on hardware can still win; TimeChain aims for auditable failure, not magic.

---

## Deployment Modes
### Local Single-Node STRICT (this white paper)
Intended for:
- personal provenance systems,
- workstation “proof spine,”
- private research audit trails,
- local-first integrity appliances.

STRICT means:
- missing required evidence can’t be waived.
- unknown enums are failures.
- suspicious seams are receipts, not stories.

### Extensions (future)
- Multi-device federation (without claiming consensus)
- Optional external anchoring to public logs or blockchains (commitments only)
- Hardware-backed secure enclaves for signer isolation

---

## Implementation Notes (for builders)
This white paper is backed by an implementation-grade spec. If you’re building:
- Use canonical JSON profile + pinned hashing/signing input.
- Enforce integer-only uncertainty arithmetic.
- Treat pinset digests and policy digests as first-class verifier inputs.
- Build verifiers as dumb deterministic machines: `ACCEPT/QUARANTINE/REJECT` + bounded reason codes + optional tripwire action.

**Minimum viable TimeChain (toy to real):**
1) hashchain ticks + signatures
2) per-second Merkle roots (empty root defined)
3) witness sample sets + bounds intersection
4) widening during offline
5) bounded reason codes + fail-closed verifier output
6) basic tripwire action (LOCKDOWN)
7) recovery receipts (manual + restart epoch)
8) add attestation and counters as hardware permits

---

## Use Cases
- **Personal epistemic receipts:** “This happened” with time uncertainty explicitly represented.
- **High-integrity journaling:** tamper-evident, rollback-resistant timelines without relying on the wall clock.
- **Research provenance:** ordering and commit roots for datasets, experiments, and results.
- **Regulated environments (internal):** evidence-grade time claims with sealed recovery rituals.
- **Forensics:** explicit seams and anomalies improve post-incident interpretability.

---

## Comparison Snapshot (what we do differently)
| Property | Typical timestamped logs | TimeChain |
|---|---|---|
| Event order | derived from wall time | derived from monotonic order |
| Offline behavior | silently wrong or snapped | honest degradation + widening |
| Witness trust | often implicit | pinned + auditable |
| Failure handling | warnings / best effort | deterministic tripwires |
| Recovery | silent fixes common | explicit receipts + scar seams |
| Export privacy | precise timestamps leak | coarse buckets + bounded metadata |

---

## Roadmap (credible next steps)
1) **Reference verifier implementation** (deterministic, fail-closed) + fixture runner  
2) **Witness adapters** for NTS-NTP, Roughtime, and GNSS (policy-pinned)  
3) **TPM integration** for quotes and NV counters  
4) **External anchoring module** for epoch commitments (optional)  
5) **Formal verification targets**: invariants for ordering, bounds widening, and tripwire correctness

---

## Conclusion
TimeChain replaces “timestamp faith” with evidence discipline. It forces time uncertainty to be explicit, makes witness influence auditable, and turns integrity violations into irreversible scars requiring explicit recovery receipts. This is not the friendliest stance; it is the stance you adopt when the system’s job is to preserve integrity under pressure.

---

## Appendix: Where to find the spec artifacts
- **TimeChain Spec (Local STRICT):** `AEVUM:SPEC:TIMECHAIN:LOCAL_STRICT:V1_0`  
- Pinned policies/registries: canonical JSON profile, Merkle profile, reason-code registry, TripwirePolicy, witness pinset rotation, bounds widening, fork detection, evidence requirements, key lifecycle, vault sealing, recovery protocol.
