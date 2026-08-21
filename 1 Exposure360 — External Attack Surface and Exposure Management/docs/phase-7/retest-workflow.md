# Retest Workflow

1. A human completes approved source-system work outside Exposure360.
2. A task enters `RESOLVED_PENDING_VERIFICATION`.
3. An analyst requests a retest with approved scope, scope version, approval, authorized target, protocol, and idempotency key.
4. `ScopeGuard` validates the request and emergency-stop controls remain applicable.
5. A verification run records queued/running/completed/partial/failed/cancelled outcome, current evidence timing, integrity, completeness, target correctness, and scope validity.
6. The mandatory closure gate records an immutable decision.

No retest endpoint performs firewall, DNS, cloud-policy, account, patching, shell, credential, or other source-system mutation.
