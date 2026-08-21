# Phase 7 Test Evidence

## Local backend quality gate — 2026-08-21 UTC

```text
OTEL_SDK_DISABLED=true uv run ruff check .
OTEL_SDK_DISABLED=true uv run ruff format --check .
OTEL_SDK_DISABLED=true uv run mypy exposure360_api
OTEL_SDK_DISABLED=true uv run pytest -q
```

Result: **298 passed**, Ruff clean, 120 files formatted, and strict mypy reported no issues.

## Gateway configuration validation

The Caddy 2.8 configuration validated in an isolated AWS container. The parameterized compose configuration also validated on the AWS Docker host without altering the running deployment. A private temporary gateway used loopback HTTPS, internal TLS, narrow CORS preflight, and private upstreams. At that point AWS still ran the Phase 6 baseline, so `/api/v1/risks` correctly returned 404 through the proxy; Phase 7 deployment evidence remains pending.

## Managed dashboard quality gate

`pnpm check`, `pnpm test`, and `pnpm build` passed: TypeScript clean, 13 unit tests passed, and production build completed. Visual route capture reached the existing unsigned managed-dashboard authentication shell; live authenticated gateway E2E remains pending DNS/TLS activation and a signed-in Phase 7 user session.
