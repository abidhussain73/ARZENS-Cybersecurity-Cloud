# Phase 4 Security Test Plan

The Phase 4 acceptance suites use SQLite in-memory databases with foreign-key enforcement, fixture payloads, deterministic clocks, and the in-memory private evidence-store double. No Phase 4 test sends an active scan, DNS, TCP, TLS, HTTP, or external discovery request.

| Control | Verification |
|---|---|
| Organization isolation | Composite keys, repository validation, and direct cross-organization API/evidence/ownership/fingerprint test cases. |
| Canonical identity | Deterministic normalization, per-organization uniqueness, and no certificate or redirect merge semantics. |
| Lifecycle safety | Monotonic timestamp, stale policy, explicit retirement, and future-time rejection tests. |
| Ownership safety | Claim precedence/conflict, idempotency, same-asset evidence links, privileged manual override, and audit tests. |
| Evidence privacy | Server-generated keys, bounded streaming, viewer authorization, no public/static URL, signed TTL limit, filename sanitization, and audit tests. |
| Evidence integrity | SHA-256 verification, deliberate tamper test, and missing-object detection. |
| Signature safety | YAML schema/allowlists, duplicate rejection, bounded timeout-capable regex checks, and no dynamic execution. |
| API boundary | Pagination/filter tests, no evidence bytes, 404 direct cross-org denial, and no graph route in OpenAPI. |

The verified focused suites are `test_canonical_assets.py`, `test_canonical_promotion.py`, `test_asset_lifecycle.py`, `test_ownership.py`, `test_evidence_records.py`, `test_evidence_store.py`, `test_technology_signatures.py`, `test_fingerprint_evaluator.py`, and `test_canonical_api.py`.
