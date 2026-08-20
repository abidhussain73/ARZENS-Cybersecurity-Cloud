# Evidence Storage Security

The `EvidenceObjectStore` protocol centralizes private object-store behavior. Domain services and HTTP handlers do not use a MinIO/S3 client directly. The production adapter is S3-compatible and uses configured credentials; the test adapter is in-memory and offline only.

Object keys are generated server-side in this form:

```text
organizations/<organization-id>/evidence/<yyyy>/<mm>/<evidence-id>/<sha256>
```

No caller supplies an object key, so traversal segments cannot enter the key. Uploads stream through a bounded spool and enforce `EVIDENCE_MAX_OBJECT_BYTES`; allowed media types are constrained with `application/octet-stream` as the safe default. The adapter never requests a public ACL or emits a static public URL. Optional platform server-side encryption can be configured for deployments that support it.

Downloads require a valid organization context and viewer-or-higher role before `head` or signed URL generation. The signed reference is capped at 300 seconds, no signed token is logged, the generated filename strips control characters and path separators, and `evidence.download_authorized` is audited. Integrity verification streams bytes, recomputes SHA-256, and distinguishes `HASH_MISMATCH` from `OBJECT_MISSING`.
