# Verified Control Freshness

`VERIFIED` evidence can be considered by the reducer only when it remains current and valid. `STALE`, `INVALID`, `REVOKED`, and expired evidence have a mandatory applied reduction of zero. The Phase 7 risk detail API exposes this as `reduction_applied: 0`; the dashboard renders **“STALE — no risk reduction applied.”**

This behavior is covered by persistence, reducer, and API contract tests. No control evidence is treated as secret material in the API response.
