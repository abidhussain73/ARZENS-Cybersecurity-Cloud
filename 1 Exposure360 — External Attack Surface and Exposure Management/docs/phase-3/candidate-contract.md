# Candidate Staging Contract

## Purpose

`CandidateAsset` is a non-canonical hint. It may be a `DOMAIN`, `IP`, or `ENDPOINT_HINT`; it is not a Phase 4 asset, service, endpoint, risk, or finding.

## Required Contract Fields

| Field | Requirement |
|---|---|
| Organization, scope, version, approval IDs | Mandatory and UUID-valid |
| Contract version | Mandatory; identifies producing schema |
| Candidate type | `DOMAIN`, `IP`, or `ENDPOINT_HINT` only |
| Raw and canonical values | Raw retained for provenance; canonical normalized centrally |
| Source key / source record key | Required source identity; record key optional where unavailable |
| Observed timestamp | Timezone-aware source time; never replaced with retrieval time |
| Metadata | JSON-safe, provider-specific fields contained here only |
| Confidence hint | Bounded source signal, not authorization |

## Identity and Provenance

Candidate identity is `(organization_id, scope_version_id, candidate_type, canonical_value)`. Domain and IP candidates never collapse into one record. Source observations remain separate and use a deterministic key derived from source key, record key, payload hash, and source observation time. Replays therefore do not inflate confidence.

## Confidence

Confidence uses a versioned, explainable model. Independent evidence categories combine deterministically; repeated observations of one category do not multiply the score. The stored explanation identifies model version, category weights, and combined score. It is never used as permission to execute a network operation.
