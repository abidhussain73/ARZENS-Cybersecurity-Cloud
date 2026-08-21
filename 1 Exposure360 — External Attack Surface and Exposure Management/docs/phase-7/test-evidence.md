# Phase 7 Test Evidence

## Local backend quality gate — 2026-08-21 UTC

```text
OTEL_SDK_DISABLED=true uv run ruff check .
OTEL_SDK_DISABLED=true uv run ruff format --check .
OTEL_SDK_DISABLED=true uv run mypy exposure360_api
OTEL_SDK_DISABLED=true uv run pytest -q
```

Result: **298 passed**, Ruff clean, 120 files formatted, and strict mypy reported no issues.

## AWS private deployment and gateway validation

The AWS Compose stack was rebuilt from the isolated Phase 7 branch and Alembic advanced from `0018_relationship_graph` to `0021_verification_runs (head)`. The persistent Caddy gateway is bound to `127.0.0.1:8443`, uses private internal TLS, and leaves the API and Keycloak upstream bindings private. Deployed validation confirmed `GET /gateway/health = 200`, unauthenticated `GET /api/v1/risks = 401`, and the restricted API preflight response = `204` for the configured origin. A real local Keycloak token then accessed the organization-scoped protected risk endpoint through the loopback HTTPS gateway with `200`; the self-cleaning fixture data was removed afterward.

The self-cleaning fixture-only acceptance harness obtained a real local Keycloak token and exercised deployed contextual risk, a stale verified control with zero reduction, policy-backed remediation/SLA, exception approval, ScopeGuard retest denial, verification listing, and analytical attack-path safety flags. It completed with `phase7_aws_acceptance=passed fixture_only=true source_system_mutation=false` and deleted its synthetic organization records.

## Managed dashboard quality gate

`pnpm check`, `pnpm test`, and `pnpm build` passed: TypeScript clean, 13 unit tests passed, and production build completed. Visual route capture reached the existing unsigned managed-dashboard authentication shell; live authenticated gateway E2E remains pending DNS/TLS activation and a signed-in Phase 7 user session.
