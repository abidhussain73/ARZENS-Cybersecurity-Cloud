# Lifecycle Semantics

Asset timestamps retain three separate facts: `observed_at` records when a source saw a fact, `collected_at` records when Exposure360 retrieved it, and `ingested_at` records canonical acceptance. All application-generated timestamps are UTC.

`first_seen` is the minimum valid observation time and can move earlier after historical import. `last_seen` is the maximum valid observation time and never regresses for an out-of-order observation.

| State | Meaning | Automatic transition policy |
|---|---|---|
| `ACTIVE` | Recently observed under the organization’s freshness policy | Normal valid observation may activate. |
| `STALE` | Not recently confirmed | Policy evaluation may mark stale. |
| `RETIRED` | Explicit authoritative/manual retirement | Never set from one failed scan. |

Future timestamps are rejected and freshness settings are organization/type scoped through `asset_freshness_policies`.
