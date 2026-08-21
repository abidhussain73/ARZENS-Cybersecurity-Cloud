# ADR 009 — Retest Evidence Freshness

## Decision

Only evidence collected at or after verification-run start may satisfy the evidence-current requirement.

## Rationale

This prevents an older clean observation from closing an ongoing exposure condition.
