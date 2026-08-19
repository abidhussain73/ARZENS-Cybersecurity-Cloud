# Phase 1 Test Evidence

| Check | Command / method | Result |
|---|---|---|
| Supplied host SSH | Dedicated key with strict known-hosts record | Connected; Ubuntu 24.04 x86_64, 2 vCPU, 7.7 GiB RAM, 17 GiB free. |
| Docker runtime | Docker Engine and Compose installation | Docker 29.1.3 and Compose v2.40.3 installed. |
| Compose config | `docker compose config --quiet` | Passed. |
| Compose startup | `docker compose up -d --build` | Built and started all declared services. |
| Scheduler repair | Beat log after writable schedule path change | Passed; scheduler reports `beat: Starting...`. |
| Migration | `alembic -c /alembic.ini upgrade head` | Passed; database revision `0002_membership_timestamps`. |
| Service baseline | `docker compose ps` on supplied host | API, web, worker, scheduler, PostgreSQL, Redis, MinIO, Keycloak, and OTel Collector are running; PostgreSQL and Redis health checks report healthy. |
| API metrics | `curl http://localhost:8000/metrics` | Passed; Prometheus text exposition is available from the API. |
| Loopback hardening | API/web Compose port bindings and post-restart logs | Passed; API is bound to `127.0.0.1:8000`, web to `127.0.0.1:8080`, and API logs confirm successful liveness and readiness responses after restart. |
| Runtime snapshot | `docker compose ps --format json` | All nine declared services are running; PostgreSQL and Redis report healthy, and no stateful service has a public host port. |
| Backend locked quality | `uv sync --locked && uv run ruff check . && uv run ruff format --check . && uv run mypy exposure360_api && uv run pytest` | Passed locally on 2026-08-19T08:33:00Z: Ruff and format checks passed, mypy found no issues, and 6 tests passed. |
| OIDC discovery/JWKS | API internal request to Keycloak discovery plus live token validation | Passed on 2026-08-19T08:40:00Z. Discovery issuer matched the configured internal issuer; the issued access token contained the configured API audience and deterministic Alice subject. |
| Protected `/api/v1/me` | Private API-container acceptance script | Passed on 2026-08-19T08:40:00Z. Unauthenticated request returned 401; two valid Alice requests returned 200 with the same user ID and a correlation response header. |
| Membership fixtures | `python -m exposure360_api.dev_fixtures` and PostgreSQL query | Passed on 2026-08-19T08:41:00Z. Alice is analyst in ORG-A, Bob is analyst in ORG-B, and coordinator is owner in both. |
| Cross-organization isolation | Private API-container acceptance script against `/api/v1/organizations/context` | Passed on 2026-08-19T08:41:00Z. Alice with ORG-A returned 200/analyst; changing only `X-Organization-ID` to ORG-B returned 403. |
| Privileged audit action | Coordinator membership deactivation plus PostgreSQL verification | Passed on 2026-08-19T08:42:00Z. The action returned 200 with `phase1-audit-20260819`; its persisted audit record is `membership.deactivate`, ORG-B, coordinator subject, and `success`. |
| Mandatory configuration negative path | `pytest tests/test_config.py` | Passed on 2026-08-19T08:50:00Z. Removing mandatory environment values causes named `ValidationError` fields including `app_base_url`, `database_url`, and `oidc_issuer_url`. |
| Structured-log redaction | `pytest tests/test_logging.py` | Passed on 2026-08-19T08:50:00Z. Direct and nested authorization, password, API-key, and database-URL values are replaced by `[REDACTED]`. |
| Complete backend quality | `uv run ruff check . && uv run ruff format --check . && uv run mypy exposure360_api && uv run pytest` | Passed on 2026-08-19T08:50:00Z. Ruff and formatting passed, mypy found no issues in 12 source files, and all 11 tests passed. |
| Full service health matrix | Private host liveness/readiness, Redis, PostgreSQL, Keycloak, MinIO, worker, and scheduler checks | Passed on 2026-08-19T08:50:00Z. API liveness/readiness returned 200; Redis returned `PONG`; PostgreSQL returned `1`; internal Keycloak discovery returned 200; MinIO created and listed the acceptance bucket; worker was ready; scheduler dispatched and worker completed recurring heartbeat tasks. |
| Probe metric | Protected `/api/v1/observability/probe` before/after metric comparison | Passed on 2026-08-19T08:49:00Z. The protected request returned 200 and `exposure360_worker_tasks_enqueued_total` changed after enqueueing the safe task. |
| End-to-end trace | Correlated protected probe plus detailed Collector debug export | Passed on 2026-08-19T08:49:00Z. API and worker JSON events share correlation `phase1-trace-20260819c` and trace `cff9990ed2075fdaf0e46390f545da85`; Collector exported `observability_probe.database`, `observability_probe.api`, and `observability_probe.worker` spans under the same trace ID. |
| JSON runtime logs | API and worker Compose logs for the protected probe and recurring heartbeat | Passed on 2026-08-19T08:50:00Z. API completion, API enqueue, worker completion, and scheduler-heartbeat events are JSON objects with service, environment, timestamp, and applicable correlation/trace fields. |
| Frontend lock and quality | Pinned `pnpm@9.15.4`; `pnpm install --frozen-lockfile`, lint, typecheck, Vitest/RTL, and build | Passed on 2026-08-19T08:58:00Z. ESLint and strict `tsc --noEmit` passed; 4 Vitest/RTL shell tests passed; Vite production build completed. |
| Frontend browser shell | `pnpm test:e2e` with system Chromium | Passed on 2026-08-19T08:58:00Z. Playwright verified the application shell, secure sign-in control, organization selection, and explicit server-validation notice. |
| Locked container graph | API/worker/scheduler `docker compose up -d --build --force-recreate` using `uv export --locked` | Passed on 2026-08-19T09:00:00Z. All three images built from `uv.lock`, started successfully, and post-rebuild API/web/worker/scheduler runtime checks passed. |
| Repository clone and controls | `git clone --no-local` plus ownership/workflow/secret-pattern inspection | Clone succeeded on 2026-08-19T09:00:00Z. CODEOWNERS and CI exist, no tracked `.env`, PEM, or key files matched the safety check, and remote branch protection remains documented as manual. |

Unexecuted checks remain unaccepted and must not be represented as passing.
