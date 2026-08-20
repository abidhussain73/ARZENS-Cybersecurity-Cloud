# Ownership Model

Ownership is represented as historical claims in `asset_ownerships`, not a single mutable owner field. Each claim has a deterministic claim key, source, confidence, validity window, and optional display name. `ownership_evidence_links` binds claims to evidence in the same organization and for the same asset.

| Claim type | Resolution precedence |
|---|---:|
| `MANUAL` | 3 |
| `SOURCE_ASSERTED` | 2 |
| `INFERRED` | 1 |

Within a claim type, deterministic ordering uses confidence, source precedence, valid time, and stable identifier. Near-equal competing owners remain visible as `OWNERSHIP_CONFLICT`; they are not silently discarded. Manual assignment requires `admin` or `owner` and writes `asset.ownership_manual_assigned` to the Phase 2 audit trail.
