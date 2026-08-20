# ADR-0011: Candidate Staging Identity Is Version-Scoped and Non-Canonical

## Status

Accepted.

## Context

Phase 3 needs durable discovery hints while Phase 4 canonical asset identity has not been authorized. A global asset key would prematurely merge records across scopes and organizations, leak ownership context, and blur source evidence.

## Decision

Candidate identity is the unique tuple `(organization_id, scope_version_id, candidate_type, canonical_value)`. Candidate rows retain scope ID and approval ID for provenance. Domain, IP, and endpoint hints remain distinct. `candidate_assets` is explicitly staging-only and cannot be used as a Phase 4 asset/service/finding model.

## Consequences

Concurrent/replayed source ingestion upserts one candidate within a version while preserving source observations. An approved replacement scope version deliberately creates a distinct staging namespace rather than mutating prior job evidence.
