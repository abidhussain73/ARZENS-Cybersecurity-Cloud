# Phase 1 Decisions

## D-001 — Isolated implementation boundary

The strict Phase 1 package is maintained under `exposure360-phase1-foundation` so it does not modify or misrepresent the separate managed Exposure360 dashboard, which contains later-phase capabilities.

## D-002 — Supplied-host deployment

The user-provided Ubuntu AWS host is the validation environment. Docker Compose ports are loopback-only and stateful services have no host-port publication.

## D-003 — Repository governance gap

The isolated package directory is initialized locally. Remote branch protection remains an external administrative action and is documented in `docs/operations/branch-protection.md`; it is not represented as enabled.

## D-004 — Standards-based OIDC API verification

The API verifies bearer access tokens through the configured issuer discovery document and cached JWKS signing keys. PyJWT validates signature, issuer, audience, expiration, and not-before claims. The Keycloak realm fixture provides a PKCE-capable browser client and deterministic local-only subjects, while the API derives application membership exclusively from PostgreSQL rather than token roles.

## D-005 — Explicit organization context

Organization context is supplied through `X-Organization-ID`, but the header is never trusted in isolation. Every request to an organization-context endpoint resolves the authenticated user’s active membership for the requested organization and returns 403 when no membership exists. The minimal `/api/v1/organizations/context` endpoint exists only to verify this foundation behavior.

## D-006 — Atomic membership audit event

Membership deactivation and the associated `audit_events` insert share one SQLAlchemy session and one transaction commit. The audit helper stores safe redacted metadata and the request correlation ID, while later observability work adds the active trace ID.
