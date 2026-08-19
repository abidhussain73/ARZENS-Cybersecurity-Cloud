# Discovery Job State Machine

```text
QUEUED -> RUNNING -> COMPLETED
                 -> DEGRADED
                 -> PARTIAL
                 -> FAILED
QUEUED/RUNNING -> CANCELLING -> CANCELLED
```

## Transition Rules

| State | Meaning | Allowed next state |
|---|---|---|
| QUEUED | Accepted but not executing | RUNNING, CANCELLING, FAILED |
| RUNNING | At least one enabled stage executing | COMPLETED, DEGRADED, PARTIAL, CANCELLING, FAILED |
| CANCELLING | Durable cancellation request has been recorded | CANCELLED |
| COMPLETED / DEGRADED / PARTIAL / FAILED / CANCELLED | Terminal | No execution transition |

Every job includes stage records for passive source, certificate import, reconciliation, DNS, TCP, TLS, HTTP, and finalization as configured. A stage is `QUEUED`, `RUNNING`, `COMPLETED`, `PARTIAL`, `SKIPPED`, `FAILED`, or `CANCELLED`.

Finalization is idempotent. Cancellation, emergency stop, scope disablement, or approval expiry prevents new active operations. A job that collected useful output before a permanent per-target failure is `PARTIAL`; a source limitation that permits continued work is represented as `DEGRADED` details rather than falsely reporting success.
