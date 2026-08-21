# Factor Availability

| State | Meaning | Risk treatment |
|---|---|---|
| AVAILABLE | Current valid evidence exists | Included in raw-score numerator and denominator |
| MISSING | Applicable source is absent | Excluded from score calculation but included in coverage denominator |
| STALE | Evidence exceeds freshness policy | Excluded from score calculation but included in coverage denominator |
| INVALID | Integrity, schema, or quality failed | Excluded from score calculation but included in coverage denominator |
| NOT_APPLICABLE | Factor does not logically apply | Excluded from coverage denominator |

The scorer is deterministic for the same inputs and evaluation time. It clamps scores to 0–100 and exposes low coverage rather than declaring unavailable context safe.
