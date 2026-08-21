# Relationship Model

Phase 6 adds organization-scoped `ExternalContextEntity`, `Relationship`, and `RelationshipEvidenceLink` models. Nodes are either canonical assets or bounded external context. Relationships are directional, evidence-backed, time-aware, and have deterministic SHA-256 identity.

| Invariant | Enforcement |
|---|---|
| Exactly one endpoint reference per side | Database XOR constraints |
| Same organization | Repository authorization lookup |
| Repeated import | Identity reuse, retained first seen, advanced last seen |
| Provenance | Idempotent evidence/source-record link |
