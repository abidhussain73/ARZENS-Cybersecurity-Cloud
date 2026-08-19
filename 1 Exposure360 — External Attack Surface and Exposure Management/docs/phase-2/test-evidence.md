# Phase 2 Test Evidence

| Check | Command / method | Result |
|---|---|---|
| Phase 1 local regression prerequisite | Locked backend lint/format/mypy/pytest; frontend lint/type/test/build/Playwright | Passed on 2026-08-19 before Phase 2 changes: 11 backend tests, 4 frontend tests, and 1 browser test. |
| Phase 1 supplied-host prerequisite | Compose service matrix, health, migration, Redis, Keycloak probe | Passed on 2026-08-19: nine services running, API/web healthy, Alembic `0002_membership_timestamps`, Redis `PONG`, Keycloak discovery `200`. |

Phase 2 evidence is appended only after commands are executed successfully.

## Phase 2 Execution Evidence — 2026-08-19 UTC

| Check | Command / method | Result |
|---|---|---|
| Backend strict quality gate | `cd apps/api && uv run ruff check . && uv run ruff format --check . && uv run mypy exposure360_api && uv run pytest` | PASS: Ruff and formatter clean; mypy reports no issues across 18 source modules; **70 passed** in 1.18 seconds. |
| Scope governance persistence | Alembic migration `0003_scope_governance`; AWS container `alembic -c /alembic.ini current` | PASS: all Phase 2 governance tables are represented by the schema migration; AWS reports `0003_scope_governance (head)`. |
| Normalization and conflicts | `tests/test_scope_normalization.py`, `tests/test_scope_conflicts.py` | PASS: 21 canonicalization/domain-CIDR-IP-ASN tests and 3 conflict-precedence tests pass using documentation-reserved values only. |
| Approval immutability and policy | `tests/test_scope_approval.py`, `tests/test_scan_policy.py`, `tests/test_governance_api.py` | PASS: immutable non-draft edits, content-hash authorization, schedule, protocol, rate, and concurrency rules pass; API lifecycle test submits and approves a real in-memory database scope. |
| Emergency stop and running-operation observation | `tests/test_emergency_stop.py`, `tests/test_scope_guard.py` | PASS: organization stop takes precedence; scope stop/resume works; an already-running fake guarded operation invokes transport once before a stop and is denied before its next request. |
| Governance API and audit trail | `tests/test_governance_api.py` | PASS: create, seed, exclusion, policy, validation, submit, approval, rejection, scope stop/resume, and organization stop/resume endpoints run through FastAPI against a real SQLite database. Cross-organization read returns 403. Required audit action names and the shared `phase-two-api-test` correlation ID are asserted. |
| OpenAPI contract snapshot | `docs/api/openapi.json` generated from `exposure360_api.main:app` under the deterministic test environment | PASS: 68,168-byte generated OpenAPI 3.1 snapshot captures the typed `/api/v1/scopes`, versions, target, policy, approval, and stop/resume route contracts. |
| Guarded transport boundary | `tests/test_scope_guard.py` | PASS: 17 guard cases verify exact/subdomain and CIDR allow paths, lookalike/out-of-scope/excluded targets, ASN non-executability, approval expiry, scope/org stop, policy denial, cross-org version, hash mismatch, schedule, and rate/concurrency. Every deny case asserts fake transport calls remain zero. |
| Frontend strict gate | `./node_modules/.bin/tsc --noEmit && ./node_modules/.bin/eslint src e2e --max-warnings=0 && ./node_modules/.bin/vitest run && ./node_modules/.bin/vite build` in `apps/web` | PASS: strict TypeScript and ESLint clean; **9 Vitest tests** pass; production Vite build succeeds. |
| Browser primary workflow | `./node_modules/.bin/playwright test` in `apps/web` | PASS: **3 browser tests** pass. The required scope lifecycle uses the actual local FastAPI governance router and a deterministic SQLite organization fixture—no browser network routes are mocked. It verifies create scope → normalize seed → add exclusion → configure policy → validate → submit → approve → approved read-only. The two pre-existing browser tests remain as contract/shell coverage. |
| Supplied AWS runtime | rsync source, `docker compose build api web`, recreate API/web, HTTP readiness checks | PASS: API `/health/live`, `/health/ready`, and `/api/v1/openapi.json` all return HTTP 200. The live OpenAPI document contains `/api/v1/scopes`; API and web containers are recreated from the Phase 2 source. |
| Hosted repository CI | GitHub Actions run [`32244201235`](https://github.com/abidhussain73/ARZENS-Cybersecurity-Cloud/actions/runs/32244201235) on the published `main` revision | PASS: `backend-quality`, `frontend-quality`, and `compose-config` all completed successfully. The frontend job provisions the locked API environment and executes the real FastAPI-backed Playwright workflow. |

The AWS host does not include the local `uv` development executable, so static analysis and test suites were executed in the locked local development environment. The deployed container runtime was independently verified through migration, health, OpenAPI, and service recreation checks.
