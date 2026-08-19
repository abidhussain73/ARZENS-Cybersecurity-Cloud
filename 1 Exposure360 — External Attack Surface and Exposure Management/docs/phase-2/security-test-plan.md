# Phase 2 Security Test Plan

The test suite verifies organization-scoped repository predicates, server-side role checks, immutable approved content, deterministic canonical parsing, exclusion precedence, transactional active-version selection, expiry, schedule boundaries, rate/concurrency denial, and stop precedence.

Guard tests use only the reserved documentation targets `example.com`, `192.0.2.0/24`, `198.51.100.0/24`, `2001:db8::/32`, and `AS64500`. They use mocked transports and assert exactly zero transport calls whenever a target is excluded, outside scope, invalid, expired, disabled, stopped, cross-organization, hash-mismatched, protocol-blocked, or outside schedule. No public network traffic is generated.

Browser tests cover draft creation, normalization preview, conflict status, submit/approve flow, approved read-only state, emergency stop/resume, and safe error rendering. Integration tests verify audit actor, organization, correlation ID, scope, version, approval, and redacted metadata.
