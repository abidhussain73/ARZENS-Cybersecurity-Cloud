# Observation and Evidence Model

`canonical_observations` store normalized source facts. An observation idempotency key hashes organization, asset, observation type, source identity, observed time, and canonical payload hash. Replays return the existing fact; temporally distinct source facts remain distinct.

`evidence` records immutable provenance metadata. SHA-256 is computed over canonical JSON bytes—sorted keys, compact separators, UTF-8, and no non-finite numbers. Cookie and `set-cookie` material is removed from metadata before persistence.

| Property | Enforcement |
|---|---|
| Organization consistency | Composite foreign keys and service validation |
| Idempotency | Organization-scoped unique idempotency keys |
| Source time | `source_observed_at`, `collected_at`, and `stored_at` remain distinct |
| Immutability | SQLAlchemy update listener rejects hash, key, size, source-time, collection-time, and storage-time alteration |
| Sensitivity | `PUBLIC_METADATA`, `INTERNAL_METADATA`, or `RESTRICTED` |
