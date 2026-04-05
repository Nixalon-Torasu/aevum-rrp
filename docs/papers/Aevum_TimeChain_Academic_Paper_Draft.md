# Time as Evidence: The Aevum TimeChain for Single-Node Provenance with Drift-Resilient Bounds, Pinned Witnesses, and Fail-Closed Recovery
**Author(s):** <Author Name(s)>  
**Affiliation(s):** <Affiliation(s)>  
**Contact:** <email>  
**Date:** 2026-01-23  

## Abstract
Time is a fragile primitive in provenance and attestation systems: wall-clock timestamps can be forged, drift silently under offline operation, and invite coercive disclosure when exported at full precision. This paper presents the **Aevum TimeChain**, a single-node, append-only time integrity spine that treats time as **evidence** rather than authority. The TimeChain emits **1-second ticks** that (i) establish total order via a device monotonic clock, (ii) represent UTC only as **bounded intervals** with explicit uncertainty growth under witness loss, (iii) commit per-second event sets across multiple chains using deterministic Merkle roots, and (iv) enforce fail-closed behavior through bounded reason codes, deterministic tripwires, vault sealing, and receipt-based recovery. The result is a drift-resistant, oracle-poisoning-resistant, coercion-aware temporal backbone suitable for verifiable local provenance without distributed consensus.

**Keywords:** secure logging, provenance, timestamping, monotonic clocks, NTP/NTS, Roughtime, Merkle trees, append-only ledgers, rollback detection, remote attestation

---

## 1. Introduction
Timestamps are routinely treated as objective truth: an event “happened at time *t*.” In practice, wall-clock time is a local claim dependent on oscillator stability, operating system behavior, network conditions, and adversarial manipulation. In provenance ledgers and audit systems, over-trusting wall-clock timestamps creates three recurring failure modes:

1. **Forgery and rollback:** An attacker can shift the clock, replay a prior disk image, or fabricate event order while retaining plausible timestamps.
2. **Offline ambiguity:** When a device is disconnected, drift grows; upon reconnection, systems often “snap” the clock and silently rewrite perceived time.
3. **Coercive leakage:** Precise timestamps can reveal sensitive behavior patterns even when content is encrypted.

The Aevum TimeChain is designed for a different stance: **time is evidence, not truth**. Instead of asserting a precise UTC timestamp, each tick records (a) monotonic order and (b) an uncertainty interval bounding plausible UTC, expanding predictably when witnesses disappear. The system makes seams explicit (reboot/suspend/clock steps) and treats integrity violations as irreparable scars that require explicit recovery receipts.

### 1.1 Contributions
This paper contributes:
- A deterministic, implementation-grade **single-node time integrity spine** using 1-second ticks and monotonic ordering.
- A data model that encodes UTC as **bounded intervals** derived from **pinned witness evidence**, with explicit quality states and anomaly receipts.
- Pinned **canonical encoding**, **hashing**, **signature input**, and **Merkle profiles** to prevent cross-implementation drift.
- A fail-closed verifier interface with a bounded **reason-code registry** and deterministic **TripwirePolicy** (“cruel by table”: lockdown/seal/recover).
- Conformance fixture guidance to support interoperable producers and verifiers.

---

## 2. Background
### 2.1 Time synchronization as evidence
Network Time Protocol (NTP) is widely used for wall-clock synchronization, but unauthenticated NTP is vulnerable to spoofing and manipulation. Network Time Security (NTS) adds cryptographic authentication to NTP exchanges, improving resistance to on-path attackers [1,2]. Roughtime provides verifiable time assertions from servers and supports client-side validation of responses [3]. GNSS provides time but is vulnerable to jamming/spoofing and must be treated as fallible evidence.

### 2.2 Append-only commitments
Tamper-evident logs are commonly built by chaining hashes over entries and periodically anchoring commitments externally. Merkle trees provide efficient set commitments [4], while transparency systems such as Certificate Transparency demonstrate practical append-only logging with verifiability [5].

### 2.3 Order vs. time
Logical clocks provide order without claiming absolute time [6]. Hybrid logical clocks (HLC) blend physical time with logical counters to tolerate drift in distributed settings [7]. The TimeChain adopts a stricter single-node formulation: monotonic order is primary; UTC is expressed only as bounded evidence.

---

## 3. System and Threat Model
### 3.1 System model
A single device produces:
- An append-only **TimeChain** of 1-second ticks.
- Additional append-only chains (e.g., perception, interaction, physiology, reality) whose per-second event sets are committed by the TimeChain tick.

The device may have:
- A monotonic clock source (nanoseconds).
- Optional attestation capability (e.g., TPM quotes).
- Optional monotonic counters (e.g., TPM NV counters) for rollback detection.

External witnesses (NTS-protected NTP, Roughtime, GNSS) are evidence providers and are not trusted unconditionally.

### 3.2 Threat model
We consider:
- **Local tampering:** modification, deletion, or reordering of stored chain records.
- **Rollback:** restoring a prior snapshot of storage to erase events.
- **Oracle poisoning:** forging witness time evidence.
- **Silent key substitution:** changing signing keys without trace.
- **Seam lying:** reboot/suspend/clock step without explicit receipts.
- **Coercion:** requiring high-resolution time exports.

Security goals:
- Tamper-evidence and replay detection by construction.
- Oracle poisoning resistance via witness pinning, quorum, and skew limits.
- No silent key changes and no silent recovery.
- Reduced coercive leakage via coarse export policy.

---

## 4. Design Requirements
**R1 (Determinism):** Canonical encoding, hashing, signature input, and Merkle construction are pinned and identical across implementations.  
**R2 (Order-first):** Monotonic order is primary; UTC claims are bounded intervals only.  
**R3 (Evidence discipline):** Witness use is explicit, pinned, auditable; witness loss degrades quality state and widens bounds.  
**R4 (Fail-closed):** Missing required evidence or policy mismatch fails closed under STRICT.  
**R5 (No silent seams):** Reboots/domain changes/clock steps emit explicit anomaly receipts.  
**R6 (Cruel by table):** Integrity violations trigger deterministic tripwire actions (lockdown/seal) rather than discretion.  
**R7 (Coercion resistance):** Public exports are coarse-bucketed and omit witness endpoints and fine-grained monotime.

---

## 5. The Aevum TimeChain
### 5.1 Overview
Each second, the producer emits a **TimeChainTick** that includes:
1. `time_block_id` (strictly increasing),
2. monotonic interval (`tick_start_ns`, `tick_end_ns`),
3. UTC bounds (`t_min_utc_ns`, `t_max_utc_ns`),
4. `time_quality_state`,
5. per-chain Merkle roots for the second,
6. references to evidence records: witness sample set, optional attestation, optional monotonic counter receipt, anomaly receipts.

Ticks are hash-chained and signed, yielding tamper-evidence and verifiable continuity.

### 5.2 Evidence-bound UTC
A tick never asserts exact UTC. It asserts an interval:
\[
[t_{\min}, t_{\max}] \subset \mathbb{Z}
\]
in nanoseconds since epoch, derived from evidence and widened deterministically under witness loss.

### 5.3 Deterministic canonicalization, hashing, signing
The spec pins:
- Canonical JSON serialization (sorted keys, minimal separators, UTF-8),
- SHA-256 digesting for `payload_hash` and `event_hash`,
- signature input as the raw 32-byte `event_hash`.

These choices eliminate cross-language ambiguity and prevent “equivalent but different” encodings.

### 5.4 Deterministic Merkle commitments
For each chain, events are sorted deterministically and committed by a Merkle root. Empty chains commit to a constant empty root. A verifier can recompute and compare roots to ensure each tick commits to the exact per-second event set.

---

## 6. Witness Evidence and Bounds
### 6.1 Pinned witnesses and rotation
Witnesses are pinned in a **WitnessPinset** identified by digest. A tick and its witness sample set must agree on the pinset digest. Pinset rotation is append-only governance with a STRICT default of **no overlap**, preventing silent oracle drift.

### 6.2 Baseline bounds intersection
Given witness intervals \([w^i_{\min}, w^i_{\max}]\), the baseline bound is:
\[
t_{\min} = \max_i w^i_{\min}, \qquad t_{\max} = \min_i w^i_{\max}
\]
If \(t_{\min} > t_{\max}\), evidence is inconsistent; the tick becomes ANOMALOUS and references an anomaly receipt.

### 6.3 Offline/holdover widening (integer-only)
When witnesses are absent or insufficient, bounds widen deterministically using integer-only math based on:
- baseline uncertainty,
- drift budget (ppm),
- elapsed monotonic time since last SYNCED state.

This ensures uncertainty cannot be “smoothed away” without receipts.

### 6.4 Leap seconds
Leap second handling is policy-pinned (SMEAR or BOUNDS_ONLY). Monotonic ordering remains intact; UTC uncertainty may widen during leap windows.

---

## 7. Quality States and Evidence Requirements
Quality states are bounded:
- **SYNCED:** witness quorum and skew satisfied; bounds derived from pinned evidence.
- **HOLDOVER:** partial witness loss; deterministic widening.
- **OFFLINE:** witness absence; aggressive widening.
- **ANOMALOUS:** evidence conflict or integrity anomaly; requires anomaly receipts and conservative uncertainty floors.

For each state, the spec pins which evidence references are REQUIRED vs OPTIONAL. Under STRICT, missing required evidence causes REJECT.

---

## 8. Fail-Closed Verification, Tripwires, and Recovery
### 8.1 Bounded reason codes
Verifiers output bounded reason codes from a registry. Unknown enums are a failure. This prevents verifier drift and makes failure semantics interoperable.

### 8.2 TripwirePolicy (“cruel by table”)
Reason codes map deterministically to actions. Certain failures—rollback evidence, fork detection, hashchain breaks, unpinned witnesses, attestation bind mismatches—trigger **LOCKDOWN** and vault sealing. No discretion.

### 8.3 Vault sealing semantics
Sealing is a state machine controlling allowed operations (append, decrypt-read, export). Severe failures enter a hard seal mode that may forbid exports.

### 8.4 Recovery protocol (no silent recovery)
Returning to normal after lockdown requires explicit receipts in order:
1. Manual unseal receipt,
2. fresh monotonic counter receipt,
3. fresh attestation,
4. fork evidence + resolution (if applicable),
5. key rotation with roll-forward proofs,
6. recovery epoch genesis (“scar”) linking to the prior epoch head.

Integrity failures become auditable seams.

---

## 9. Privacy and Coercion Resistance
Public exports are designed to be coercion-resistant:
- timestamps are coarse-bucketed (policy-tunable; e.g., 15-minute buckets),
- witness endpoints and fine-grained monotime are omitted,
- exports include digests and bounded reason codes rather than narratives.

---

## 10. Evaluation and Discussion
### 10.1 Security analysis (qualitative)
- **Tamper-evidence:** hash chaining and signatures detect modification.
- **Rollback detection:** monotonic counter receipts provide explicit rollback evidence.
- **Oracle poisoning resistance:** pinned witnesses and rotation controls reduce substitution attacks.
- **Seam integrity:** anomaly receipts and recovery scars prevent silent continuity claims.

### 10.2 Operational cost
Per tick: hashing for payload/envelope, per-chain Merkle roots, and optionally witness sampling/attestation/counter reads. The cadence is constant and predictable.

### 10.3 Limitations
- Single-node STRICT provides strong local integrity but not distributed consensus.
- Witness availability varies; the system prefers honest degradation over false precision.
- Attestation and counters depend on hardware; file-based counters are weaker than TPM NV counters.

---

## 11. Related Work
The TimeChain composes established primitives—hash chains, Merkle commitments, authenticated time protocols, and secure logging—into a strict single-node temporal backbone whose distinguishing feature is **evidence-first** time semantics and **deterministic fail-closed recovery**:
- Authenticated time and verifiable evidence: NTP/NTS [1,2], Roughtime [3].
- Tamper-evident logs and transparency: Merkle trees [4], Certificate Transparency [5].
- Ordering without authority: Lamport clocks and related ordering frameworks [6,7].
- Hardware roots: TPM attestation and monotonic counters [8].

---

## 12. Conclusion
The Aevum TimeChain demonstrates a strict alternative to wall-clock-centric provenance: it treats time as evidence, pins witness identities, encodes UTC only as bounded intervals, and makes seams and failures explicit via receipts. Deterministic encoding and bounded semantics enable interoperable verification, while fail-closed tripwires and recovery rituals ensure that integrity violations leave auditable scars rather than being silently “fixed.” This posture is intentionally conservative: when evidence weakens, uncertainty grows and quality degrades rather than fabricating precision.

---

## References
> **Workflow note:** For a project this size, use Zotero + Better BibTeX and keep a single shared `.bib` for the Aevum corpus. Pin specs (RFCs, FIPS, TCG) as “standards” entries and cite them consistently across papers.

[1] D. Mills et al., “Network Time Protocol Version 4: Protocol and Algorithms Specification,” **RFC 5905**, IETF, 2010.  
[2] E. S. Jones et al., “Network Time Security for the Network Time Protocol,” **RFC 8915**, IETF, 2020.  
[3] Roughtime Project, “Roughtime: Secure Time Synchronization,” specification/whitepaper, 2018.  
[4] R. C. Merkle, “A Digital Signature Based on a Conventional Encryption Function,” in *Advances in Cryptology—CRYPTO ’87*, 1988.  
[5] B. Laurie, A. Langley, and E. Kasper, “Certificate Transparency,” **RFC 6962**, IETF, 2013.  
[6] L. Lamport, “Time, Clocks, and the Ordering of Events in a Distributed System,” *Communications of the ACM*, 1978.  
[7] Hybrid Logical Clocks (HLC) literature—cite the canonical paper selected by your venue and implementation lineage.  
[8] Trusted Computing Group, “TPM 2.0 Library Specification,” (version as implemented), 2014–2021.  

---

## Appendix A: Artifact list (for reproducibility)
- **TimeChain Spec (Local STRICT):** `AEVUM:SPEC:TIMECHAIN:LOCAL_STRICT:V1_0`  
- Canonical JSON profile, Merkle profile, reason-code registries  
- TripwirePolicy, witness pinset rotation policy, bounds widening profile  
- Evidence requirements policy, key lifecycle policy, vault seal policy, recovery protocol  
- Conformance fixtures (JSON traces) with expected verifier verdicts
