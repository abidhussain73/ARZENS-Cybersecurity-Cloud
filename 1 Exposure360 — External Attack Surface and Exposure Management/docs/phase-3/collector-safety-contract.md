# Collector Safety Contract

All DNS, TCP, TLS, and HTTP collectors consume the same Phase 2 `ScopeGuard`. No collector reimplements domain matching, exclusion precedence, approval validation, or stop behavior.

Immediately before each resolver/transport call, the collector must verify the pinned job references, current approval, scope enablement, current emergency-stop state, protocol, schedule, rate/concurrency budget, target address safety, and `ScopeGuard` result. Ambiguity, database failure, guard failure, or stale authorization causes denial.

| Operation | Guarded dependency | Required denial proof |
|---|---|---|
| DNS | Resolver | Resolver calls = 0 |
| TCP | Socket transport | Transport calls = 0 |
| TLS | TLS transport | Transport calls = 0 |
| HTTP and redirect | HTTP transport | Unauthorized hop calls = 0 |

The production path contains no bypass flags such as skip authorization, allow-all targets, or disable emergency stop. Tests use injected fakes and local fixtures, never production bypass configuration.
