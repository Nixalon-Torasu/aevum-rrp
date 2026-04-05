# Aevum Technical Specification (ATS) — Packet ATS-v0.1

This document is NORMATIVE. MUST/MUST NOT/SHOULD/MAY are interpreted per RFC 2119.

Packet contents:
- Schemas: ./schemas (JSON Schema 2020-12)
- Registries: ./registries (kinds/enums/errors)
- Conformance: ./conformance (profiles + vectors + runner contract)
- Packet integrity: ./packet.json + ./PACKET_FILES.json

If this document conflicts with shipped schemas or conformance vectors, schemas/vectors are authoritative for machine-checkable behavior and the conflict is a spec defect.

## 1. Canonical Encoding (json.jcs.v1)
All signed bytes and hashed bytes MUST be RFC 8785 canonical JSON encoded as UTF-8 (json.jcs.v1).

Numeric rule (ATS v0.1):
- Floating-point numbers MUST NOT be produced.
- Verifiers MUST reject non-integers in signed/hashed objects (E_CANON).

## 2. Domain-Separated Hashing
H(tag,msg) = SHA256( "AEVUM" || 0x00 || tag || 0x00 || msg )

HASHSTR(digest) = "sha256:" + lowercase hex.

Domain tags used by v0.1:
- payload.v1, envelope.v1, block.v1
- event_digest.v1
- range_step.v1, range_root.v1
- export_file.v1, export_step.v1, export_root.v1
- ats_packet_file.v1, ats_packet_step.v1, ats_packet_root.v1
- conformance_file.v1, conformance_step.v1, conformance_root.v1

## 3. Envelope (aevo.envelope.v1)
Schema: ./schemas/aevo.envelope.v1.schema.json

Signature scope:
- Sig = Ed25519 over JCS(envelope.signed)
- kid identifies the verifying pubkey (see keyring.v1)

Payload integrity:
- If signed.payload: payload_hash MUST equal HASHSTR(H("payload.v1", JCS(payload)))
- If signed.payload_ref: payload bytes are retrieved by payload_hash; locator is non-authoritative.

Envelope ID:
- ENVELOPE_ID = HASHSTR(H("envelope.v1", JCS(envelope)))

## 4. TimeChain Blocks
Schema: ./schemas/timechain.block.v1.schema.json

Genesis:
- height=0 prev_block_hash MUST be sha256:00..00.

Event digest:
- event_hashes MUST be sorted lexicographically by raw hash bytes.
- event_digest = HASHSTR(H("event_digest.v1", 0x01 || concat(event_hashes_bytes)))

Block ID:
- BLOCK_ID = HASHSTR(H("block.v1", JCS(block)))

## 5. Finalization
Schema: ./schemas/timechain.finalize.v1.schema.json

range_root:
- acc = 32*0x00
- for i in [start..end]:
  acc = H("range_step.v1", acc || U64BE(i) || BLOCK_ID_BYTES(i))
- range_root = HASHSTR(H("range_root.v1", acc || U64BE(start) || U64BE(end)))

## 6. Export Manifest (ledger.export.manifest.v1)
Schema: ./schemas/ledger.export.manifest.v1.schema.json

Each file_index entry uses:
- file.sha256 = HASHSTR(H("export_file.v1", raw_bytes))

bundle_hash is computed over sorted file_index using export_step.v1/export_root.v1 (see conformance vectors).

## 7. Conformance
Profiles: ./conformance/profiles.json
Vectors: ./conformance/vectors/manifest.v1.json

## 8. Change Control
Spec defects MUST be fixed by publishing a new packet and adding conformance vectors that detect the defect.
