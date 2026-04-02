AEVUM:POLICY:RECEIPTS_NONBLOCKING:V1

Principle
- Receipts are evidence and optimization inputs. They MUST NOT be used as gates.

Operational requirements (core behavior)
- Processing MUST proceed without requiring the receipt layer to be present.
- If receipt writing is unavailable (disk full, permissions, crash), the system MUST:
  - continue processing (best-effort),
  - record a runtime error signal (stderr/syslog/metrics),
  - and when possible, emit explicit gap markers or fault receipts later (time gaps are already modeled in TimeChain).

Forbidden uses
- Using receipts (or lack of receipts) for friction/scoring/escalation, or to force identity/narrative.
- Using the narrative rail to control core functions.

Implementation hint (Year-1)
- Run receipt printers as separate services from any interactive processing loop.
- Treat verifier/indexer as optional accelerators (caches/checkpoints), not prerequisites.
