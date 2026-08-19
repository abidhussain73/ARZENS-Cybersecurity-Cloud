# Discovery API Examples

The APIs are organization-scoped and use the existing organization header and bearer-token conventions. Job creation accepts only existing governed scope references, never arbitrary raw targets.

```http
POST /api/v1/discovery/jobs
X-Organization-ID: <organization-id>
Idempotency-Key: optional-safe-client-key

{"scope_id":"<scope-id>","scope_version_id":"<approved-version-id>"}
```

The accepted response is `202` and includes job ID, state `QUEUED`, pinned scope/version identifiers, UTC creation timestamp, and links to self/cancel resources.

```http
GET /api/v1/discovery/jobs/<job-id>
GET /api/v1/discovery/jobs/<job-id>/stages
GET /api/v1/discovery/jobs/<job-id>/events?limit=50
GET /api/v1/discovery/jobs/<job-id>/dead-letters?limit=50
POST /api/v1/discovery/jobs/<job-id>/cancel
```

Status exposes truthful counts, stage, known-total or indeterminate progress, safe failure classes, degraded sources, and UTC timestamps. It never exposes provider credentials, stack traces, raw HTTP bodies, cookies, internal topology, or transport secrets.
