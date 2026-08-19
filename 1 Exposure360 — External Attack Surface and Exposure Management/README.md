# Exposure360 — Strict Phase 1 Foundation

This directory is an isolated implementation of **Exposure360 Phase 1 only**. It supplies the engineering runtime: a React/Vite shell, FastAPI API, Celery worker and scheduler, PostgreSQL, Redis, MinIO, Keycloak, and OpenTelemetry Collector. It deliberately does **not** implement scopes, assets, discovery, findings, risk, reporting, or remediation.

## Local prerequisites

Install Docker Engine with the Compose plugin. Copy `.env.example` to `.env` only for local development; never place production credentials in the repository.

## Startup and checks

```bash
cp .env.example .env
docker compose up -d --build
curl http://localhost:8000/health/live
curl http://localhost:8000/health/ready
docker compose ps
```

The web shell is published on port `8080` and the API on `8000` for local developer use. Database, Redis, object storage, identity, and telemetry ports remain internal to Compose by default.

## Quality commands

```bash
cd apps/api && uv run ruff check . && uv run ruff format --check . && uv run mypy exposure360_api && uv run pytest
cd ../web && pnpm lint && pnpm typecheck && pnpm test && pnpm build
```

## Security model

The API verifies OIDC JWTs server-side, resolves memberships from PostgreSQL, validates every requested organization context, and writes correlation-aware audit records for privileged membership changes. Development credentials belong only to the version-controlled Keycloak realm fixture; they are not production credentials.

See `docs/architecture/phase-1-architecture.md`, `docs/operations/local-development.md`, and `docs/phase-1/acceptance-report.md` for the operating and evidence record.

