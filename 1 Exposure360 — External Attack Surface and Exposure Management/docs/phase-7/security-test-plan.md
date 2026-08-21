# Security Test Plan

Phase 7 security coverage verifies tenant-scoped risk/task/SLA/verification access, viewer mutation denial, reviewer/admin exception boundaries, ScopeGuard retest denial without valid scope inputs, bounded pagination, no generic remediation close action, stale control zero reduction, immutable closure records, and API/OpenAPI route presence.

The gateway design adds an HTTPS-only public activation path while retaining private API and identity upstreams. The application verifies public-issuer JWT claims against a private Keycloak JWKS endpoint so the API does not require a public reflection path. The committed default binds the gateway to loopback and uses internal TLS until a real domain is provided.
