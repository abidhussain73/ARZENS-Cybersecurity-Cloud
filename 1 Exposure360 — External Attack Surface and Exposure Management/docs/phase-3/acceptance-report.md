# Exposure360 Phase 3 Acceptance Report

## Revision

| Field | Value |
|---|---|
| Starting commit | `fcc313b` |
| Starting migration head | `0003_scope_governance` |
| Starting environment | Local deterministic tests plus supplied AWS Compose runtime |
| Final implementation commits | `b4dd1f9`, `20677a7`, `4e15392` |
| Final local backend gate | Ruff, formatter, strict mypy, and **154 pytest tests** passed. |
| Final web gate | TypeScript, ESLint, **11 Vitest tests**, production Vite build, and **4 Playwright scenarios** passed. |
| AWS migration/runtime | `0004_discovery_staging` applied; readiness, discovery OpenAPI paths, seven staging tables, API/worker log checks, and self-cleaning recorded-source fixture acceptance passed. |

## Prerequisite Regression

Phase 1 and Phase 2 regression passed before Phase 3 implementation. Organization isolation, ScopeGuard fail-closed behavior, approvals, scan policy, emergency stop, governance API/UI, and protected worker/runtime baseline were verified.

## Authoritative Tasks

| Task | Result | Evidence |
|---|---|---|
| EX360-T021 | PASS | Versioned candidate/source/batch/checkpoint contracts, additive migration SQL rendering, and schema tests pass. |
| EX360-T022 | PASS | Fixture-only passive-DNS adapter contract, deterministic pagination, scope relevance, and normalized candidate tests pass. |
| EX360-T023 | PASS | Fixture-only certificate adapter safely extracts scope-relevant SAN/CN/wildcard-base candidates and persists provenance through the central reconciler. |
| EX360-T024 | PASS | Version-scoped candidate identity, provenance-preserving observation upsert, replay-stable explained confidence, and concurrent unique-key test pass. |
| EX360-T025 | PASS | Pinned durable orchestration uses expiring fenced leases, source-stage restart/replay, terminal checkpoints, configured-fixture worker execution, and ID-only Celery task delivery. The real task body is verified against SQLite for stage completion, terminal checkpoint persistence, idempotent redelivery, and finalization. Durable progress is verified for both indeterminate and known-total queued/remaining states. |
| EX360-T026 | PASS | Injected fixture-only A/AAAA validation invokes ScopeGuard before resolution, persists bounded staging outcomes and rebinding metadata, classifies NXDOMAIN/timeout safely, and never schedules special/private/documentation addresses for downstream active validation. The resolver zero-call denial matrix and configured worker-stage integration passed. |
| EX360-T027 | PASS | TCP validation uses explicit HTTPS/HTTP/TLS port allowlists, fresh ScopeGuard authorization, resolved-address safety, and policy concurrency checks before connector use. The real standard-library connector has explicit timeout coverage without live network traffic; excluded-IP zero-call proof and configured worker-stage checkpoint/progress integration pass. |
| EX360-T028 | PASS | Guard-first TLS metadata collection permits only explicit TLS ports after a prior successful TCP gate, persists metadata-only certificate facts, proves complete zero-handshake denials, has a monkeypatched real-connector no-network test, and exercises bounded retry/dead-letter recovery. |
| EX360-T029 | PASS | Bounded HTTP metadata collection uses safe URL/header/body handling, manual redirect authorization on every hop, HEAD-to-GET fallback, redirect loop/limit protection, excluded and out-of-scope zero-call evidence, durable endpoint-hint worker staging, and bounded retry evidence. |
| EX360-T030 | PASS | Durable cancellation convergence, bounded retry events, idempotent dead-letter upsert/requeue, truthful degraded outcome, and ten-candidate interruption/restart replay evidence pass against SQLite. |
| EX360-T031 | PASS | Organization-isolated FastAPI endpoints provide `202 Accepted` creation, stable-ID-only queueing, list/detail/progress, cancel, stages, events, dead letters, role checks, audit events, cross-organization denial, and regenerated OpenAPI. |
| EX360-T032 | PASS | Responsive React discovery jobs list/detail UI presents all lifecycle states, truthful indeterminate progress, per-stage status, recovery details, event log, and cancellation control with unit and Playwright coverage. |

## Final Gate

**PHASE 3 ACCEPTED.** All EX360-T021 through EX360-T032 requirements have reproducible local test/build evidence and AWS runtime verification. The implementation remains inside the hard Phase 3 boundary: candidate staging is version-scoped and non-canonical, and no Phase 4 canonical asset or exposure-management feature was implemented.
