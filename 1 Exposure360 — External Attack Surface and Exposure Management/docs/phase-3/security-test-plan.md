# Phase 3 Security Test Plan

| Boundary | Negative test | Required proof |
|---|---|---|
| ScopeGuard | Out-of-scope, excluded, expired, disabled, or stopped operation | Resolver/transport calls = 0 |
| DNS | Non-approved name, blocked DNS policy, schedule end | Resolver call count = 0 |
| Address safety | Public name resolving to private/special IP | DNS observation retained; active calls = 0 |
| TCP | Unsupported port/protocol | Socket calls = 0 |
| TLS | Denied/stopped/unsupported protocol | TLS calls = 0 |
| HTTP | Unsafe scheme, URL credentials, redirect escape | Unauthorized hop calls = 0 |
| HTTP memory | Local oversized/chunked fixture | Reader stops at configured cap |
| HTTP time | Local slow fixture | Bounded timeout result |
| Recovery | Stop during retry backoff | Retry transport call = 0 |
| Isolation | Cross-organization job/candidate query | 403/404 and no data leak |
| Redaction | Fixture cookie/token | Raw values absent from storage/log output |

All tests use injected transports, deterministic fixtures, documentation addresses, and Compose-local services only. Test mode must not disable ScopeGuard, policy, or emergency-stop enforcement.
