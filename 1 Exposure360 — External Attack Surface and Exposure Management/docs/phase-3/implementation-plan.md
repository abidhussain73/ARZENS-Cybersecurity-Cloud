# Exposure360 Phase 3 Implementation Plan

## Scope and Baseline

Phase 3 implements only `EX360-T021` through `EX360-T032`: candidate staging, safe source collection, guarded network metadata collection, orchestration, APIs, and progress UI. It will not implement Phase 4 canonical assets, identity consolidation, fingerprinting, findings, risk, remediation, or an asset inventory.

The accepted baseline is local foundation revision `fcc313b` with migration head `0003_scope_governance`. The prerequisite local regression passed: 70 backend tests, 9 frontend unit tests, and 3 browser tests. Docker is unavailable in the development sandbox, so runtime Compose verification was run on the supplied AWS host; all nine accepted services were healthy, API live/readiness endpoints returned 200, and the deployed migration remained at `0003_scope_governance`.

## Implementation Sequence

| Wave | Tasks | Deliverable | Safety gate |
|---|---|---|---|
| Contracts and schema | T021 | Versioned discovery contracts and staging migration | Mandatory organization, scope, version, and approval references |
| Passive discovery | T022–T024 | Recorded source adapters, provenance-preserving reconciliation, confidence | Fixture-only sources; no adapter creates ORM records directly |
| Orchestration | T025 | Pinned jobs, durable stages/checkpoints, truthful progress | At-least-once delivery with idempotent persistence |
| Active metadata | T026–T029 | DNS, TCP, TLS, HTTP collectors | Guard-first and rechecked immediately before every transport call |
| Resilience | T030 | Cancellation, bounded retry, dead letters | Stop/cancel interrupts new work and backoff |
| Product surface | T031–T032 | RBAC API and accessible progress UI | No raw target input, secrets, bodies, or traces exposed |
| Acceptance | Final | Fixture-only integration, AWS verification, evidence | No Phase 4 model or unauthorized transport path |

## Runtime Placement

The existing API creates and reads durable PostgreSQL records. Redis/Celery receives only IDs and safe trace/correlation headers. The worker processes bounded stages and writes authoritative state, checkpoints, and events to PostgreSQL. MinIO is optional staging storage for safe, hashed source artifacts; it does not become a public evidence retrieval system. The browser polls truthful job status at a bounded interval and stops polling terminal jobs.

## Migration and Rollback Strategy

The Phase 3 migration will be additive. It will retain all Phase 1 and 2 tables unchanged, add foreign keys to organizations/scopes/approved versions, and add practical staging indexes and unique keys. Downgrade instructions will describe the incompatibility of removing discovery staging data; no rollback will delete valid governance configuration. Queued jobs will be cancelled/drained before a destructive rollback is considered.

## Test Fixture Topology

Acceptance will use recorded passive-DNS and certificate fixtures, injected resolver/transports, and local fixture services only. Test targets use documentation ranges and fixture-only endpoints. No test depends on public DNS, public websites, or a live passive provider.

## Phase Boundary

Candidate rows are staging hints only. A candidate confidence score is neither authorization nor risk. Active operations are authorized only by the existing `ScopeGuard`, current policy, current approval, stop state, schedule, and address-safety checks.
