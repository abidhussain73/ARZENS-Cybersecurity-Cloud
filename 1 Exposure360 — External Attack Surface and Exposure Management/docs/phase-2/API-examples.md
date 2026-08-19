# Phase 2 API Examples

All state-changing and read operations require a valid bearer token and the existing `X-Organization-ID` header. Organization ownership is derived server-side.

```http
POST /api/v1/scopes
X-Organization-ID: <authorized-org>

{"name":"Fixture External Estate","description":"Reserved test targets"}
```

```http
POST /api/v1/scopes/<scope>/versions/<version>/seeds
X-Organization-ID: <authorized-org>

{"seed_type":"DOMAIN","raw_value":"EXAMPLE.COM.","match_mode":"DOMAIN_AND_SUBDOMAINS"}
```

The response returns `raw_value: "EXAMPLE.COM."` and `canonical_value: "example.com"`. Version submit, approval, emergency stop, and resume responses expose state, content hash, timestamps, and safe approval information. Error responses use a stable code and the request correlation ID without raw stack traces.
