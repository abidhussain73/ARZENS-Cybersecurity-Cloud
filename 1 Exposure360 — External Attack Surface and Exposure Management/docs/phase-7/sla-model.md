# SLA Model

Phase 7 uses **Simple Calendar v1**: all durations are elapsed UTC seconds with no holiday or local-business-calendar semantics.

| Priority | Resolve duration |
|---|---:|
| P1 | 24 hours |
| P2 | 72 hours |
| P3 | 7 days |
| P4 | 30 days |

An SLA instance retains the policy version, start time, resolve/verify/final due times, pause time, accumulated pause duration, and state. The API returns the recorded versioned policy, not an arbitrary UI-selected date.
