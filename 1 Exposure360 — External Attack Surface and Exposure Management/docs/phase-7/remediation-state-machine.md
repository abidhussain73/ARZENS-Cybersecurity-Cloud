# Remediation State Machine

| State | Allowed next state(s) |
|---|---|
| OPEN | PLANNED, IN_PROGRESS, BLOCKED, CANCELLED |
| PLANNED | IN_PROGRESS, BLOCKED, CANCELLED |
| IN_PROGRESS | BLOCKED, RESOLVED_PENDING_VERIFICATION, CANCELLED |
| BLOCKED | PLANNED, IN_PROGRESS, CANCELLED |
| RESOLVED_PENDING_VERIFICATION | IN_PROGRESS, BLOCKED; verification service only can progress closure |
| VERIFIED | CLOSED |
| CLOSED / CANCELLED | OPEN |

The explicit `start` and `resolve-pending-verification` task actions synchronize the associated finding through the established audited lifecycle service. Invalid actions return `INVALID_REMEDIATION_TRANSITION`. Generic workflow code cannot self-verify or self-close a task.
