# Checkpoint and Resume Semantics

Checkpoints are durable, versioned, JSON-safe records. They include source key, adapter version, checkpoint schema version, stage, and token/index. They are never deserialized as executable objects.

The worker follows this order: persist idempotent candidate/observation or collector attempt; commit the transaction; then persist/advance the checkpoint. It deliberately implements at-least-once delivery with idempotent handling, unique keys, and safe upserts rather than claiming distributed exactly-once execution.

| Stage | Checkpoint value |
|---|---|
| Passive/certificate source | Provider pagination token or record index |
| Candidate validation | Last candidate identity and batch sequence |
| HTTP metadata | Last endpoint-hint identity |

If an adapter version is incompatible with a checkpoint, the worker classifies the failure safely rather than silently deserializing or continuing. Duplicate queue delivery, source page replay, and worker interruption must leave one authoritative candidate and one idempotent observation per source record.
