# Discovery Source Adapter Contract

## Interface

Every passive source implements a provider-neutral adapter with `source_key`, `adapter_version`, capabilities, health, `collect(scope_context, checkpoint)`, and `normalize(record)`. The adapter accepts only a scope-derived context and a JSON-safe checkpoint; it has no access to API/UI state and cannot persist ORM entities.

## SourceBatch

| Field | Meaning |
|---|---|
| `records` | Bounded provider-neutral records |
| `next_checkpoint` | JSON-safe resumable position or `null` |
| `source_observed_at` | Source time, if batch-level |
| `retrieved_at` | Local collection time in UTC |
| `partial` / warnings | Explicit reduced-result signal |
| `rate_limit_state` | Bounded source-limit information |

## Errors and Health

Source errors are classified as transient, rate-limited, authentication, authorization, invalid-response, permanent, or partial. Health is `HEALTHY`, `DEGRADED`, `UNAVAILABLE`, or `MISCONFIGURED`. Authentication/configuration errors are not retried indefinitely. CI uses only recorded adapters and fixtures; optional live providers require explicit configuration references and never store credentials in database rows.

## Recorded Adapters

The initial passive-DNS and certificate adapters use deterministic pagination and fixture records. Malformed batch schemas fail clearly; isolated malformed records are skipped with a warning/dead-letter according to the documented stage policy.
