# TCP Collection Safety

The TCP collector receives one explicit candidate endpoint and never enumerates port ranges. The Phase 3 platform allowlist is limited to TCP 80 for HTTP and TCP 443 for HTTPS/TLS, intersected with the approved scan policy and platform ceilings.

Before `open_connection`, the collector rechecks the pinned job, approval, current stop state, schedule, policy protocol, rate/concurrency budget, ScopeGuard decision, and recently validated non-special address. It uses a conservative configured timeout, records only connection success/duration/error class, and closes immediately. It does not read banners, send payloads, manipulate flags, or use raw packets.

The acceptance suite proves unsupported port, unsupported protocol, out-of-scope, excluded, stopped, and special-address cases execute zero socket transport calls.
