# Exposure360 Phase 4 Implementation Plan

## Scope

Phase 4 converts Phase 3 version-scoped candidates and recorded collection facts into an organization-scoped canonical asset inventory. The implementation ends at EX360-T041. It does not create Phase 5 findings, exposure rules, change detection, risk scores, remediation, or a final Assets UI.

## Baseline Assessment

The accepted Phase 1–3 baseline is intact. The backend gate passed Ruff, formatter, strict mypy, and 154 tests. The web gate passed TypeScript, ESLint, 11 unit tests, production build, and four Playwright scenarios. Existing Phase 3 staging remains non-canonical; Phase 4 promotion will be centralized in a new service and no discovery adapter will write canonical tables directly.

## Implementation Order

| Order | Authoritative task | Deliverable |
|---:|---|---|
| 1 | T033 | Additive migration and organization-scoped base/subtype canonical tables. |
| 2 | T034 | Deterministic canonical-key and promotion service with consolidation tests. |
| 3 | T035 | Lifecycle service with monotonic temporal semantics. |
| 4 | T037 | Idempotent observation and immutable evidence metadata model. |
| 5 | T038 | Private evidence store interface, integrity verification, and authorized retrieval. |
| 6 | T036 | Ownership claims, resolver, evidence links, RBAC, and audit behavior. |
| 7 | T039 | Versioned safe technology-rule loader and fingerprint persistence. |
| 8 | T040 | Offline HTTP/TLS/service evaluator with explainable confidence. |
| 9 | T041 | Organization-isolated canonical asset APIs and direct relationship projections. |

## Design Commitments

Canonical identity is defined by `organization_id + canonical_key`. Canonical key derivation reuses Phase 2 domain and ASN normalization and standard IP parsing. Direct subtype foreign keys express only endpoint-to-IP and service-to-endpoint/authority structure; domain-to-IP remains observation-derived. Evidence remains private, immutable by metadata contract, and is retrieved only after organization and role authorization.

## Verification Strategy

Every task will have migration, repository, unit, integration, organization-isolation, and fixture-only acceptance evidence as applicable. No Phase 4 test will make an active network request. The AWS runtime is verified only after the local full quality gate passes.
