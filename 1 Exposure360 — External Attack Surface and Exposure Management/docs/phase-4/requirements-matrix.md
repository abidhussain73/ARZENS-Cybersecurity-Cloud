# Phase 4 Requirements Matrix

| Task | Requirement | Verified evidence | Status |
|---|---|---|---|
| EX360-T033 | Canonical base, identifier, and subtype persistence | Migration `0005_canonical_assets`; repository tests | PASS |
| EX360-T034 | Deterministic identity and promotion | Key factory and organization-scoped promotion tests | PASS |
| EX360-T035 | Lifecycle timestamps and conservative state | Migration `0006_asset_lifecycle`; monotonic and stale/retired tests | PASS |
| EX360-T036 | Ownership claims and evidence linkage | Migration `0008_ownership`; precedence, conflict, RBAC, audit, and isolation tests | PASS |
| EX360-T037 | Observation/evidence hash and provenance | Migration `0007_observations_evidence`; canonical hash, sanitization, and immutability tests | PASS |
| EX360-T038 | Private evidence storage and authorized retrieval | Stream, hash, signed reference, tamper, missing-object, audit, and cross-org tests | PASS |
| EX360-T039 | Versioned technology-rule loader | YAML schema, duplicate, unsafe pattern, stable rule/ruleset hash tests | PASS |
| EX360-T040 | Offline fingerprint evaluator | Migrations `0009_technology_fingerprints` and `0010_fingerprint_confidence`; HTTP, TLS, service, version, provenance, aggregation, conflict, and isolation tests | PASS |
| EX360-T041 | Canonical asset APIs | List, detail, timeline, metadata-only evidence, direct relationship, pagination, OpenAPI, and cross-org tests | PASS |

The hard boundary is EX360-T041. Phase 5 and later features are excluded.
