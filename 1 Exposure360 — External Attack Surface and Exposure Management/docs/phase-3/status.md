# Phase 3 Status

| Task | Status | Evidence | Blocker |
|---|---|---|---|
| EX360-T021 | PASS | Contract/schema tests passed; additive migration renders from Phase 2 head. | — |
| EX360-T022 | PASS | Recorded passive-DNS fixture, adapter contract, pagination, normalization, and source-health tests pass. | — |
| EX360-T023 | PASS | Recorded certificate fixture produces scope-relevant SAN/CN candidates, wildcard-base metadata, warnings, timestamps, hashes, and a persisted CandidateObservation provenance record. | — |
| EX360-T024 | PASS | Real-database provenance/upsert/replay tests and concurrent unique-key insertion test pass. | — |
| EX360-T025 | PASS | Pinned jobs, expiring fenced leases, commit-before-checkpoint persistence, restart/replay protection, configured-fixture worker execution, real Celery task-body SQLite execution, terminal finalization, and durable typed progress are verified. | Unknown totals are explicitly indeterminate with queued `0`; known totals expose truthful queued/remaining work. |
| EX360-T026 | PASS | Fixture-only A/AAAA resolver runs only after ScopeGuard; durable collection attempts preserve resolved address, timestamp, TTL, and decision. | Resolver call count is zero for out-of-scope, excluded, emergency-stop, policy, and schedule denial paths; private/special/documentation addresses are ineligible for downstream active validation. |
| EX360-T027 | PASS | TCP validation uses ScopeGuard, fixed protocol/port allowlists, resolved-address safety, a real standard-library timeout-bounded connector, and fixture-only transport tests. | Unsupported, excluded, out-of-scope, special/private/documentation, stopped, and concurrency-exhausted operations all reach the connector with call count `0`; TCP stage checkpoint/progress integration passes. |
| EX360-T028 | PASS | Guard-first TLS metadata, complete zero-handshake denial matrix, prior-TCP gate, per-candidate checkpointing, cooperative cancellation, bounded transient retry/dead-letter evidence, fixture certificate persistence, and monkeypatched real-connector no-network evidence pass. | — |
| EX360-T029 | PASS | Bounded fixture-only HTTP metadata, initial and redirect-hop ScopeGuard authorization, zero-call excluded/out-of-scope redirects, loop/limit control, durable endpoint-hint worker stage, and bounded retry evidence pass. | — |
| EX360-T030 | PASS | Durable cancellation convergence, retry-scheduled events, numbered bounded retry attempts, idempotent dead-letter persistence/requeue, visible DEGRADED outcome, and deterministic ten-candidate interruption/restart replay all pass against SQLite. | — |
| EX360-T031 | PASS | Organization-isolated asynchronous discovery-job API supports creation, listing, detail, cancellation, stages, events, dead letters, truthful indeterminate progress, stable-ID queueing, audit events, and regenerated OpenAPI. | — |
| EX360-T032 | PASS | Discovery jobs list/detail UI exposes all lifecycle badges, truthful indeterminate progress, per-stage counts, recovery attention, event log, and cancellation control with responsive token-aligned layout. | — |

> Status may be marked PASS only after reproducible test and runtime evidence is recorded.
