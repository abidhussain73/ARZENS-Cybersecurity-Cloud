# Discovery Architecture

## Trust Boundary

Phase 3 creates non-canonical discovery staging data. A discovery job is pinned to one organization, scope, approved scope version, approval record, content hash, and policy snapshot. It never silently adopts a later scope version.

```text
approved scope version + approval + policy snapshot
    -> durable discovery job
    -> source stages and candidate reconciliation
    -> ScopeGuard decision per active operation
    -> bounded DNS / TCP / TLS / HTTP collection
    -> attempt, checkpoint, event, and staging provenance
    -> completed / partial / degraded / cancelled outcome
```

## Components

| Component | Responsibility | Authoritative store |
|---|---|---|
| API | Validate RBAC, create/cancel/read jobs, write audit events | PostgreSQL |
| PostgreSQL | Jobs, stages, checkpoints, candidates, observations, attempts, events, dead letters | PostgreSQL |
| Redis/Celery | Deliver bounded task references and trace context | Non-authoritative |
| Worker | Execute idempotent source/collector stages | PostgreSQL writes |
| ScopeGuard | Fail-closed authorization immediately before active operations | Phase 2 governance state |
| MinIO | Optional hashed staging source artifacts under organization prefix | Object storage |
| Web UI | Poll and present truthful progress/state | API only |

## State Semantics

`PARTIAL` means useful output exists with permanent per-item failures or dead letters. `DEGRADED` means a source or system limitation reduced capability while work continued. If both apply, the job state is `PARTIAL` and degraded source details remain available separately. `FAILED` is reserved for a blocking orchestration failure with no useful completion.

## Safety Invariants

1. No free-form target is accepted by job APIs or UI.
2. No source adapter writes ORM objects directly; it emits validated contracts.
3. Every active operation authorizes through Phase 2 `ScopeGuard` immediately before touching a resolver or transport.
4. Private, special, loopback, link-local, unspecified, multicast, and cloud-metadata addresses are non-connectable by default.
5. DNS results do not authorize TCP/TLS/HTTP. Downstream operations bind to a recently validated address set and recheck safety.
6. HTTP redirects are manual, bounded, normalized, and reauthorized hop by hop.
