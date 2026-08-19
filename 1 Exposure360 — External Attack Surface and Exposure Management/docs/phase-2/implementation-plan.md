# Exposure360 Phase 2 Implementation Plan

## Current Architecture and Prerequisite

Phase 2 extends the accepted isolated FastAPI, PostgreSQL, Alembic, Redis/Celery, Keycloak, OpenTelemetry, Prometheus, React/Vite foundation. The separate managed dashboard remains outside this package. On 2026-08-19, local backend quality, local frontend quality and browser coverage, plus the supplied host’s nine-service runtime, Alembic head `0002_membership_timestamps`, OIDC discovery, PostgreSQL, Redis, and loopback API/web health checks passed.

## Dependency Order

| Order | Work | Authoritative tasks |
|---|---|---|
| 1 | Organization-scoped schema, constraints, migration, and model tests | EX360-T011 |
| 2 | Shared target normalizer and static conflict analyzer | EX360-T012, EX360-T013 |
| 3 | Immutable versions, approval activation, content hash, and authorization envelope | EX360-T014 |
| 4 | Pure policy evaluation and emergency-stop state | EX360-T015, EX360-T016 |
| 5 | Typed REST API, RBAC, OpenAPI, metrics, audit trails | EX360-T017, EX360-T020 |
| 6 | Scope-administration interface and browser flow | EX360-T018 |
| 7 | Central default-deny scope guard and fake guarded transport | EX360-T019 |
| 8 | Migration, integration, browser, runtime, security, and observability acceptance | All |

## Schema and Repository Changes

The migration will add `scopes`, `scope_versions`, `scope_seeds`, `scope_exclusions`, `scan_policies`, `scope_approvals`, and `emergency_stop_states`. All are organization-owned, foreign-key constrained, and indexed for authorization and active-version lookup. Approved versions, approval records, and audit history will never be mutated or deleted. A partial unique index will ensure one active approved version per scope.

## API and Frontend Changes

New additive `/api/v1/scopes` and organization emergency-stop routes will reuse `X-Organization-ID`, OIDC, `require_org_context`, and server-side RBAC. Typed Pydantic schemas will prevent mass assignment of organization ownership. The React app will gain a focused scope-administration workflow with draft editing, normalization visibility, validation results, approval, read-only approved state, and incident controls.

## Security Assumptions

Scope evaluation is default-deny. Target normalization, matching, conflict analysis, approval validation, policy evaluation, and emergency-stop checks each have one server-side implementation. No active discovery, probing, DNS resolution, TLS handshake, HTTP request, or other Phase 3 behavior will be implemented. Test transports are in-memory doubles only.

## Testing, Migration, and Rollback

Every migration is forward-tested from the Phase 1 head and from a clean database. The migration is additive and avoids destructive changes to user, organization, membership, or audit data. A downgrade is supplied where safely possible. Backend unit, repository-contract, integration, and security tests run before deployment; frontend unit and Playwright coverage run before acceptance. Deployment rebuilds only after the local gates pass. Rollback uses the committed Phase 1 package and the migration downgrade procedure documented with the migration.

## Phase Boundary

This phase ends at EX360-T020. Candidate assets, discovery sources, DNS/TLS/HTTP probing, scanner orchestration, risk scoring, findings, and attack paths are explicitly out of scope.
