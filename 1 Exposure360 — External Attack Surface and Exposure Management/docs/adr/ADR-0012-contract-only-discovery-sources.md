# ADR-0012: Discovery Sources Emit Contracts Rather Than Persisting ORM Objects

## Status

Accepted.

## Context

Passive providers and certificate feeds can be unavailable, malformed, rate-limited, or replayed. Letting adapters write database models would mix provider parsing, authorization, provenance, retries, and persistence in unsafe ways.

## Decision

Every adapter emits versioned `DiscoverySourceContract`, `SourceBatch`, `SourceRecordContract`, checkpoint, and safe error contracts. A central reconciliation service will validate/normalize and persist them transactionally. Checkpoints are JSON-safe and versioned; adapters never deserialize untrusted executable payloads.

## Consequences

Recorded fixtures and optional live providers share an identical testable boundary. Provider credentials remain configuration references rather than database values or API/UI fields. Source adapters cannot bypass organization, scope, provenance, or idempotency rules.
