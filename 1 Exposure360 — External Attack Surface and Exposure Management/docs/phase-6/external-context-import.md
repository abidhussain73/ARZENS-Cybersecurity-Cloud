# External Context Import

The fixture adapter sorts entities and relationships deterministically. The import service resolves asset canonical keys only within its organization, upserts context and relationships, and attaches the deterministic source snapshot hash as provenance.

| Requirement | Verified fixture behavior |
|---|---|
| Idempotency | No duplicate entities, edges, or evidence links |
| Tenant isolation | Foreign assets are not resolvable |
| Reproducibility | Same normalized payload produces same source hash |
| Safe acceptance | No live integration or active scan |
