# Canonical Asset Model

Phase 4 represents durable, organization-scoped facts rather than discovery staging records. The base `assets` table is unique on **`organization_id + canonical_key`** and supports only `DOMAIN`, `IP`, `ASN`, `ENDPOINT`, and `SERVICE`. UUIDs remain storage identifiers; they are not identity semantics.

| Asset subtype | Direct structural parent | Identity boundary |
|---|---|---|
| Domain | None | Normalized FQDN |
| IP | None | Compressed IP address |
| ASN | None | Canonical ASN number |
| Endpoint | IP | TCP socket: IP, transport, port |
| Service | Endpoint; optional authority Domain | Endpoint, application protocol, authority |

`AssetIdentifier` stores aliases and source-native identifiers without changing canonical identity. Composite organization foreign keys protect subtype parents from crossing organizations. The model deliberately does **not** include a generic relationship table, vulnerability, finding, risk score, change event, or Phase 5 interpretation.

## Direct relationship boundary

The API derives one-hop relationships from subtype links and DNS observations: `RESOLVES_TO`, `HAS_ENDPOINT`, `ON_IP`, `EXPOSES_SERVICE`, `ON_ENDPOINT`, and `SERVED_FOR`. It cannot traverse or persist an arbitrary graph.
