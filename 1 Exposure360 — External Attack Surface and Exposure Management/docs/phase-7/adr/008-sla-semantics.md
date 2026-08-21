# ADR 008 — SLA Due-Date Semantics

## Decision

Use Simple Calendar v1 UTC elapsed durations and persist a versioned SLA instance at task creation.

## Rationale

The policy is repeatable, auditable, and does not depend on browser-local time or unmodeled holiday calendars.
