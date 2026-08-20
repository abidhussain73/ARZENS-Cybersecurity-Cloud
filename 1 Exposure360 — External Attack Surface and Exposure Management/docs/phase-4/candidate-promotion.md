# Candidate Promotion

`CanonicalAssetPromoter` is the boundary between Phase 3 candidates and Phase 4 facts. It performs an organization-scoped upsert using a deterministic key, persists the matching subtype and identifier, and advances temporal facts idempotently. Phase 3 adapters do not directly write canonical tables.

| Candidate outcome | Promotion policy |
|---|---|
| Domain | Valid normalized source-backed candidate may promote. |
| IP | Explicit approved seed, passive evidence, or current DNS evidence may promote. |
| Endpoint | Requires TCP reachability or authoritative endpoint evidence. |
| Service | Requires TLS, HTTP, or explicit protocol evidence. |

The promoter does not over-merge candidate objects. It maintains the `first_seen` minimum and `last_seen` maximum using source observation times.
