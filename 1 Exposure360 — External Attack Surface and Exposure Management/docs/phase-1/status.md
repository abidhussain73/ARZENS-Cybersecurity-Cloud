# Phase 1 Status

| Task | Status | Evidence |
|---|---|---|
| EX360-T001 | PASS (manual remote control outstanding) | Repository clone, CODEOWNERS, README, ignore rules, CI workflow, and the exact manual remote branch-protection checklist are present. The remote setting is explicitly not represented as configured. |
| EX360-T002 | PASS | `uv.lock` is present; locked backend Ruff, format, mypy, pytest, startup, and locked API/worker container builds pass. |
| EX360-T003 | PASS | React 19/TypeScript/Vite shell includes a typed API boundary, PKCE OIDC foundation, safe callback/error states, tokenized CSS, `pnpm-lock.yaml`, ESLint, strict type checks, Vitest/RTL, build, and Playwright evidence. |
| EX360-T004 | PASS | All nine declared Compose services are running on the supplied host. API liveness/readiness, PostgreSQL, Redis, Keycloak discovery, a MinIO bucket operation, worker readiness, and recurring scheduler heartbeat execution have verified evidence. |
| EX360-T005 | PASS | Typed Pydantic settings and safe local configuration template are present. Automated negative tests prove missing mandatory configuration fails with named validation fields and no runtime secret defaults. |
| EX360-T006 | PASS (migration) | Alembic upgraded PostgreSQL to `0002_membership_timestamps`; the migration now matches the membership timestamp model. |
| EX360-T007 | PASS | Real Keycloak discovery/JWKS signature, issuer, audience, expiration, and not-before validation is active. Live evidence proves `/api/v1/me` returns 401 without a token and 200 twice for Alice without a duplicate user profile. |
| EX360-T008 | PASS | Deterministic ORG-A/ORG-B fixtures exist. Live evidence proves Alice is allowed in ORG-A and receives 403 when only `X-Organization-ID` changes to ORG-B. |
| EX360-T009 | PASS | A coordinator deactivated Bob’s ORG-B membership. The committed audit event matches organization, actor, action, result, and the inbound correlation ID. |
| EX360-T010 | PASS | Protected probe evidence records one trace ID from API database/enqueue spans to worker execution; API and worker JSON events share the correlation ID; redaction tests pass; and the enqueue metric increments. |

No Phase 2 business feature has been added to this isolated package.
