# Canonical Asset API Contract

All routes require an authenticated principal, `X-Organization-ID`, an active organization membership, and one of the existing viewer-or-higher roles. A cross-organization UUID returns the project’s non-leaking `404` convention. Every read writes an organization-scoped audit event; the API never includes raw evidence bytes, object-store keys, or signed URLs in asset responses.

| Endpoint | Purpose | Bounded behavior |
|---|---|---|
| `GET /api/v1/assets` | Inventory list | Type, lifecycle, search, owner, technology, first/last-seen filters; offset 0–100,000; limit 1–100. |
| `GET /api/v1/assets/{id}` | Base, subtype, identifiers, ownership, technology, count summaries | Metadata only. |
| `GET /api/v1/assets/{id}/observations` | Observation timeline segment | Type, source, date filters; bounded pagination. |
| `GET /api/v1/assets/{id}/evidence` | Evidence metadata | Download remains the separately authorized T038 endpoint. |
| `GET /api/v1/assets/{id}/ownership` | Claims and primary owner | Preserves claim history. |
| `GET /api/v1/assets/{id}/timeline` | First-seen, observation, ownership, and fingerprint events | UTC-normalized ordering. |
| `GET /api/v1/assets/{id}/relationships` | One-hop direct relationships only | No graph, multi-hop traversal, path, risk, or attack-path capability. |

Asset listing is ordered by `last_seen DESC, id ASC`; secondary ID ordering keeps pagination stable. Queries are SQLAlchemy-parameterized and summaries are aggregated per list page to avoid per-row relationship traversal.
