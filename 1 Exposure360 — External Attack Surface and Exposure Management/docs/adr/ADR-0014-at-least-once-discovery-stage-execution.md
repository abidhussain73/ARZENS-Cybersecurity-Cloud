# ADR-0014: Discovery Stages Use At-Least-Once Delivery With Fenced Leases and Idempotent Persistence

## Status

Accepted.

## Context

Celery and Redis cannot provide an end-to-end exactly-once guarantee across task delivery, worker interruption, PostgreSQL persistence, and checkpoints. Claiming exactly-once would make restart behavior unsafe and unverifiable.

## Decision

Discovery jobs pin the exact scope version, immutable approval, content hash, and policy hash before queueing. Each stage has a durable record with an expiring worker token and monotonically increasing execution generation. A stale worker cannot write a checkpoint or mark a stage complete after its lease is replaced. Candidate and observation unique keys make persisted batches idempotent. A stage persists results and then commits its checkpoint in the same transaction boundary before acknowledging progress.

## Consequences

Delivery is intentionally **at least once**. A restarted worker resumes from its last committed checkpoint and may replay a batch, but does not create duplicate authoritative staging candidates or observations. Progress is based on durable counts and remains indeterminate where totals are not known. Finalization is rejected while any planned stage is queued or running.
