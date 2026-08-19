# Exposure360 Strict Phase 1 Acceptance Report

**Assessment timestamp:** 2026-08-19T09:00:00Z  
**Assessed package:** `exposure360-phase1-foundation`  
**Validation environment:** User-supplied Ubuntu AWS host, private loopback service bindings  
**Phase boundary:** `EX360-T001` through `EX360-T010` only

## Determination

> **LOCAL PHASE 1 ACCEPTED.** All ten strict Phase 1 engineering tasks have executable evidence. The only follow-up outside the package is repository-host branch protection, which is intentionally documented as an administrator-controlled manual action rather than misrepresented as active.

No Phase 2 scope governance, discovery, asset intelligence, finding, risk, reporting, or remediation capability has been implemented in this isolated package.

| Task | Determination | Verified evidence |
|---|---|---|
| EX360-T001 | PASS, with remote admin follow-up | Local Git clone succeeded; README, CODEOWNERS, `.gitignore`, CI, and no tracked environment/key files were checked. The branch-protection configuration is recorded precisely. |
| EX360-T002 | PASS | `uv.lock` exists. Locked Ruff, formatter, mypy, pytest, application startup, and locked API/worker image builds passed. |
| EX360-T003 | PASS | Pinned `pnpm-lock.yaml`; ESLint, strict TypeScript, Vitest/RTL, Vite build, and Playwright browser-shell test passed. |
| EX360-T004 | PASS | All nine Compose services are running; API, PostgreSQL, Redis, Keycloak, MinIO, worker, scheduler, web, and Collector checks passed. |
| EX360-T005 | PASS | Typed Pydantic Settings and safe local template exist; missing mandatory configuration produces clear named validation errors. |
| EX360-T006 | PASS | Alembic upgraded the database to `0002_membership_timestamps`; the schema now matches the permitted Phase 1 models. |
| EX360-T007 | PASS | Keycloak discovery/JWKS-backed bearer verification validates issuer, audience, signature, expiration, and not-before. `/api/v1/me` returned 401 without a token and 200 twice with a valid development token. |
| EX360-T008 | PASS | Deterministic ORG-A/ORG-B fixtures and server-side organization-context enforcement are present. Alice received 200 for ORG-A and 403 after changing only the requested organization to ORG-B. |
| EX360-T009 | PASS | Privileged coordinator membership deactivation returned 200; the committed audit row matched action, organization, actor, result, and `phase1-audit-20260819`. |
| EX360-T010 | PASS | API/database/enqueue/worker spans shared trace `cff9990ed2075fdaf0e46390f545da85`; structured JSON logs shared `phase1-trace-20260819c`; redaction tests and enqueue metric increment passed. |

## Acceptance Evidence Summary

The backend’s latest locked quality sequence passed Ruff lint and formatting, strict mypy checking of 12 source files, and 11 pytest tests. The frontend’s latest sequence passed ESLint, strict TypeScript, four Vitest/React Testing Library tests, Vite production build, and a Playwright application-shell test. The relevant command output and runtime probes are catalogued in [test evidence](test-evidence.md).

The deployed stack uses PostgreSQL, Redis, MinIO, Keycloak, Celery worker/scheduler, FastAPI, React/Vite, and an OpenTelemetry Collector. API and web ports remain private to the host loopback interface. The Keycloak realm emits standards-based `sub` and `aud` claims through supported protocol mappers; the API validates those claims against the issuer’s discovered JWKS rather than trusting browser role state. [1]

| Runtime area | Evidence outcome |
|---|---|
| Liveness and readiness | API `/health/live` and `/health/ready` returned successful structured responses after the final locked-image rebuild. |
| Data and queue | PostgreSQL `SELECT 1` and Redis `PING` passed; MinIO accepted a safe bucket operation. |
| Identity | Internal Keycloak discovery returned 200; valid local development tokens reached protected API endpoints. |
| Isolation and audit | Cross-organization request was rejected with 403; privileged action produced a correlated audit record. |
| Worker and scheduler | Safe observability probe completed; scheduled heartbeat was dispatched and completed repeatedly. |
| Telemetry | Detailed Collector output included API database, API orchestration, and worker spans with one trace ID. |

## Security and Operational Notes

The browser shell uses a typed API boundary and prepares Authorization Code plus PKCE parameters without persistent browser-token storage. It presents loading, unauthenticated, callback-error, permission, current-organization, current-profile, system-status, and safe fallback states. Server-side code remains the authority for token verification, membership resolution, role enforcement, audit persistence, and trace propagation.

Structured JSON logs use a recursive redaction helper for authorization, cookie, token, password, secret, API-key, and database-URL fields. Development-only identity and storage fixture values are not production credentials. The final operator must supply environment-specific production secrets through an approved secret-management path rather than modifying the checked-in template.

## Required External Follow-Up

The repository does not yet have a hosted remote managed by this workflow. Before team handoff, an authorized repository administrator must apply the exact `main` branch-protection settings in [branch-protection.md](../operations/branch-protection.md). This is an external governance control; it does not invalidate the implemented local Phase 1 runtime, but it must not be omitted during repository hosting.

## Reproducibility and Offline Boundary

Both project package managers have lockfiles: `apps/api/uv.lock` and `apps/web/pnpm-lock.yaml`. API, worker, scheduler, and web images consume their respective locked graphs during builds. The Compose runtime functions locally after images and dependencies are available. A completely air-gapped first-time build additionally requires a preloaded container-image and package cache bundle; no external dependency resolution can be performed after those artifacts are staged.

## References

[1]: https://www.keycloak.org/admin-api/protocol-mappers "Keycloak Protocol Mappers"
