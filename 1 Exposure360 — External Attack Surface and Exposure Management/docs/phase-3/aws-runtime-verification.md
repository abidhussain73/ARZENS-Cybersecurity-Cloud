# Phase 3 AWS Runtime Verification

## Verification Record

The Phase 3 foundation was synchronized to the authorized Ubuntu AWS deployment copy at `ubuntu@18.179.94.246` and rebuilt through the existing Docker Compose runtime. The deployment remains limited to the existing Phase 1–3 service topology: API, web, worker, scheduler, PostgreSQL, Redis, object storage, identity, and telemetry.

| Check | Executed evidence | Result |
|---|---|---|
| Service rebuild | `docker compose build && docker compose up -d --force-recreate` | PASS — all nine Compose services reported running; PostgreSQL and Redis reported healthy. |
| Migration | `docker compose exec -T api alembic -c /alembic.ini upgrade head` | PASS — Alembic current revision is `0004_discovery_staging`. |
| API readiness | `GET http://127.0.0.1:8000/health/ready` | PASS — database, Redis configuration, and object-store configuration reported ready. |
| Route registration | Runtime OpenAPI checked for discovery jobs and cancellation paths | PASS — `/api/v1/discovery/jobs` and `/api/v1/discovery/jobs/{job_id}/cancel` were present. |
| Persistence | PostgreSQL inspected for Phase 3 staging tables | PASS — `candidate_assets`, `candidate_observations`, `collection_attempts`, `dead_letter_items`, `discovery_checkpoints`, `discovery_job_stages`, and `discovery_jobs` exist. |
| Runtime log review | Current API and worker logs searched for traceback, exception, and error markers | PASS — no matching error entries in the reviewed post-rebuild window. |
| Integrated fixture acceptance | Self-cleaning script executed inside the deployed API container against PostgreSQL using recorded passive-DNS fixture data only | PASS — `{"acceptance":"PASS","candidate_count":4,"job_state":"COMPLETED","stage_count":8,"worker_result":"completed"}`. The temporary container script was removed and the fixture-organization count was verified as `0`. |

## Test Environment Note

The AWS deployment copy intentionally excludes development virtual environments and test caches. The full deterministic collector, recovery, API, and UI regression evidence therefore ran in the locked local development environment. In addition, the deployed runtime executed the self-cleaning recorded-source acceptance scenario above, confirming that the production Compose images, migration head, database schema, worker path, checkpoints, and staged candidate persistence are consistent with the shipped source.

## Safety Boundary

No live scanning, DNS resolution, or transport probe was executed as part of this verification. Collector acceptance remains fixture- and monkeypatch-driven, using reserved documentation targets and explicit guarded transport call-count tests.
