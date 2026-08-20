# Retry, Cancellation, and Dead-Letter Semantics

Cancellation is durable and cooperative. A user cancellation, scope/organization emergency stop, approval expiry, or scope disablement prevents new work. Workers check this state before each source batch, network operation, and retry attempt. `CANCELLING` is exposed until the worker converges to `CANCELLED`; API acceptance does not claim immediate cancellation.

Only classified transient failures receive bounded retry. The default implementation target is three attempts with capped exponential backoff and jitter for herd reduction, never evasion. Backoff waits are cancellation-aware. Authentication, scope/policy denial, malformed targets, unsupported protocols, redirect denial, and DNS NXDOMAIN are not retried indefinitely.

After exhaustion, a durable dead-letter record preserves job/stage/operation identity, attempt count, safe error class/message, timestamps, and state. Dead letters are `OPEN`, `REQUEUED`, `RESOLVED`, or `DISMISSED`. A small number of dead letters produces `PARTIAL` or `DEGRADED`, not hidden completion or unbounded requeue.
