# ADR 001 — Factor Availability

## Decision

Represent factor state as `AVAILABLE`, `MISSING`, `STALE`, `INVALID`, or `NOT_APPLICABLE` rather than only using nullable values.

## Rationale

Missing, stale, invalid, and inapplicable data have materially different confidence and coverage semantics. The decision prevents unavailable data from being interpreted as zero risk.
