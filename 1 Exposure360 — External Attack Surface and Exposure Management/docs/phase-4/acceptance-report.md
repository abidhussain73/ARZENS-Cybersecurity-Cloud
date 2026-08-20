# Exposure360 Phase 4 Acceptance Report

**Scope:** EX360-T033 through EX360-T041 only. This report records Phase 4 canonical facts, evidence, fingerprinting, and API work. It does not introduce Phase 5 findings, risk, change detection, Assets UI, or generic graph traversal.

## Completion decision

| Area | Result | Objective evidence |
|---|---|---|
| T033–T035 canonical identity and lifecycle | PASS | Canonical schema/lifecycle migrations `0005` and `0006`; deterministic key, promotion, timestamp, freshness, and state tests. |
| T036 ownership | PASS | Migration `0008`; 3 offline precedence, conflict, evidence-boundary, RBAC, and audit tests. |
| T037 observations and evidence records | PASS | Migration `0007`; 3 offline canonical hash, idempotency, sanitization, and immutability tests. |
| T038 private evidence storage | PASS | 3 offline stream, hash, size, authorized access, cross-org denial, tamper, missing-object, filename, and audit tests. |
| T039 signatures | PASS | 3 offline YAML schema, duplicate, unknown-field/operator, unsafe-regex, stable hash, version, and deterministic-sort tests. |
| T040 evaluator | PASS | Migrations `0009` and `0010`; 3 offline HTTP/TLS/service, version, provenance, replay, temporal, independent aggregation, duplicate-evidence, conflict, and cross-org tests. |
| T041 canonical APIs | PASS | 3 offline list/detail/timeline/evidence/ownership/direct-relationship/OpenAPI/cross-org contract tests. |
| Integrated local regression | PASS | Ruff clean; 73 files formatted; strict mypy clean across 40 source files; **185 passed**. |
| AWS deployment migration | PASS | Docker Compose rebuild completed and Alembic reports `0010_fingerprint_confidence (head)`. |
| AWS fixture acceptance | PASS | Self-cleaning live-schema fixture exercised list, detail, observations, evidence metadata, ownership, and relationships; all returned HTTP 200. |

## AWS acceptance evidence

The AWS fixture created a disposable organization, domain, IP, DNS observation, evidence metadata, and ownership claim inside the live PostgreSQL schema. It performed no DNS/TCP/TLS/HTTP collection or other active scanning. It asserted a direct `RESOLVES_TO` relationship and that evidence metadata did not expose an object-store key. The script cleared the fixture rows in dependency order after assertions.

```text
{'phase4_fixture': 'PASS',
 'routes': {'list': 200, 'detail': 200, 'observations': 200,
            'evidence': 200, 'ownership': 200, 'relationships': 200},
 'alembic_expected_head': '0010'}
0010_fingerprint_confidence (head)
```

## Boundary confirmation

Phase 4 is accepted only through `EX360-T041`. No Phase 5 feature is included. Canonical asset existence remains distinct from ScopeGuard authorization for all future active network work.
