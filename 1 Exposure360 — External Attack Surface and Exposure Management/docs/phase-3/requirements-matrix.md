# Phase 3 Requirements Matrix

| Task | Requirement | Prerequisite | Existing implementation | Gap | Planned modules | Tests / evidence | Status |
|---|---|---|---|---|---|---|---|
| T021 | Candidate/source/checkpoint contracts | T011 | Phase 2 scope model | Closed | `discovery_contracts`, models, migration | 9 contract/schema tests; rendered additive SQL | PASS |
| T022 | Passive adapter and recorded fixture | T021 | None | Closed | `discovery_sources` | Deterministic pagination/normalization/source contract suite | PASS |
| T023 | Certificate metadata import | T021 | None | Closed | `certificate_source`, `candidate_reconciliation` | SAN/CN, wildcard, warning, timestamp, hash, and certificate-to-provenance integration tests | PASS |
| T024 | Deduplication and confidence | T021–T023 | Phase 2 normalizer | Closed | `candidate_reconciliation` | Provenance/replay, isolation, scoring, and concurrent unique-key tests | PASS |
| T025 | Jobs, checkpoints, progress | T021, T010 | Celery worker baseline | Pinned durable orchestration, configured offline adapters, real task-body worker execution, and truthful progress complete | `discovery_jobs`, `discovery_orchestration`, worker tasks | Real Celery task-body SQLite stage/checkpoint/redelivery test; unknown- and known-total progress tests; full backend gate at 100 tests | PASS |
| T026 | Safe DNS validation | T019, T025 | ScopeGuard | Closed | `dns_validation`, `discovery_orchestration` | Fixture-only resolver call-count matrix, bounded NXDOMAIN/timeout handling, address-safety classification, and configured worker-stage integration; full backend gate at 114 tests | PASS |
| T027 | Safe TCP check | T019, T025 | Policy evaluator | Closed | `tcp_validation`, `discovery_orchestration` | Standard socket connector receives explicit timeout under monkeypatch; fixture zero-call matrix covers exclusion and denial paths; configured worker TCP stage persists checkpoint/progress; full gate at 127 tests | PASS |
| T028 | TLS metadata | T019, T027 | ScopeGuard and TCP stage | Closed | `tls_metadata`, `discovery_orchestration` | Fixture metadata, complete zero-handshake matrix, prior-TCP handoff, real connector monkeypatch, cancellation/retry/dead-letter tests | PASS |
| T029 | HTTP metadata | T019, T027 | ScopeGuard and endpoint candidates | Closed | `http_metadata`, `discovery_orchestration` | Bounded HEAD/GET, redirect authorization/limit, excluded and out-of-scope zero-call, worker-stage/retry tests | PASS |
| T030 | Cancel/retry/dead letter | T025–T029 | Emergency stop | Closed | `recovery_controls`, `discovery_orchestration` | Cancellation convergence, bounded retries, dead-letter requeue, degraded state, ten-candidate interruption/restart replay | PASS |
| T031 | Discovery API | T025, T030 | Governance router | Closed | `discovery_api` | RBAC, organization isolation, audit, queue-ID boundary, full endpoint contracts, generated OpenAPI | PASS |
| T032 | Discovery progress UI | T031 | Scope admin UI | Closed | `DiscoveryJobs`, `DiscoveryJobDetail`, `discoveryApi` | 2 discovery UI Vitest tests, full 11-test web suite, build, and 4 Playwright scenarios | PASS |
