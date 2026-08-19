# Scope Guard Contract

`ScopeGuard.authorize()` is the sole authority for a future connector request. It accepts a principal, organization, scope, scope-version, approval, raw target candidate, protocol, current time, concurrency/rate context, and correlation ID. It returns a structured allow/deny decision with a reason code, exact authorization identifiers, policy hash, and correlation ID.

The guard evaluates in this order: organization and resource ownership; active scope; organization stop; scope stop; exact version and approval validity; content-hash equality; target normalization; inclusion; exclusion; protocol; schedule; rate/concurrency. Any failure denies. The guard is called immediately before each simulated or future real transport operation, not merely when a job is created.

`GuardedNetworkClient` calls a supplied transport only after `allowed=true`. A denial raises `ScopeDenied` carrying the structured decision before the transport is reached. The Phase 2 fake transport records invocations and provides executable proof that an out-of-scope, excluded, stopped, expired, mismatched, or policy-denied request has call count zero.

The interface deliberately performs **no DNS resolution and no network transport**. A future connector must separately authorize the original logical hostname, re-authorize any resolved IP address when network policy requires it, and re-authorize every redirect target. A future long-running connector must call the guard immediately before every request or batch boundary, not only at job creation; the organization/scope stop state is deliberately reread on each authorization.
