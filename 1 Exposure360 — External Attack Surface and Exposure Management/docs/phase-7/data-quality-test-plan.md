# Data Quality Test Plan

Risk tests cover all factor availability states, effective denominator/coverage behavior, deterministic results, range clamping, banding, explanation completeness, registry hash, and tenant isolation. Control tests cover relevance, caps, verification state, expiry, stale/invalid/revoked zero reduction, and evidence visibility.

Workflow tests cover valid/invalid state transitions, UTC SLA terms, exception lifecycle, verification idempotency/active-run control, stale/degraded/tampered evidence, condition-present return to work, verified closure, and immutable decision history. No test performs active external network scanning or source-system mutation.
