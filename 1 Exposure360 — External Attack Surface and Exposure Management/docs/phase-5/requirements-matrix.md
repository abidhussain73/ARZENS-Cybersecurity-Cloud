# Exposure360 Phase 5 Requirements Matrix

**Author:** Manus AI  
**Scope:** EX360-T042 through EX360-T052 only  
**Authoritative specification:** `P01_Exposure360_Phase_5_Manus_CoT_Loop_Prompt_v1.0.md`

Phase 5 interprets canonical Phase 4 facts as exposure findings and durable changes. It does not introduce a graph, attack-path calculation, contextual risk score, exploitability score, or remediation recommendation.

| Task | Implemented capability | Local evidence | Status |
|---|---|---|---|
| EX360-T042 | Organization-scoped asset inventory/detail UI with server filters, metadata-only evidence authorization, history, and direct relationships. | Frontend typecheck, lint, production build, and focused RTL tests. | PASS |
| EX360-T043 | Immutable declarative YAML exposure-rule loader with schema validation, bounded conditions, safe operator allowlist, stable content hashes, and version synchronization. | Offline loader/repository tests. | PASS |
| EX360-T044 | Pure metadata-only HSTS, certificate, server-disclosure, and ownership evaluator. | Fixture tests and source separation from transport collectors. | PASS |
| EX360-T045 | Evidence-backed Finding lifecycle with RBAC, validated transitions, state events, exception rules, and audit records. | SQLite constraint and lifecycle tests. | PASS |
| EX360-T046 | Deterministic finding fingerprinting, temporal updates, recurrence reopening, and idempotent evidence links. | SQLite deduplication and temporal tests. | PASS |
| EX360-T047 | Canonical versioned snapshots with stable comparison projection and tenant-safe idempotent persistence. | Deterministic serialization and persistence tests. | PASS |
| EX360-T048 | Pure two-snapshot detector and durable ChangeEvent persistence for NEW, REMOVED, SERVICE, CERTIFICATE, OWNERSHIP, and FINGERPRINT changes. | Two-snapshot matrix, persistence, tenant-isolation, and temporal tests. | PASS |
| EX360-T049 | Time-windowed asset/type approved changes, retained EXPECTED events, audit records, and explainable `change-significance-v1` review priority. | SQLite suppression, audit, factor, clamp, and isolation tests. | PASS |
| EX360-T050 | Findings, Changes, and Approved Changes API routes with pagination, filters, detail, evidence/history, workflow actions, RBAC, and OpenAPI registration. | Four FastAPI integration tests. | PASS |
| EX360-T051 | Findings, Changes, detail, evidence, review history, exception, expected-change, and privileged approval interface. | Five Vitest suites with sixteen UI tests, lint, typecheck, production build, and Chromium finding-to-evidence/change-review workflow. | PASS |
| EX360-T052 | Versioned EvaluationRun records, bounded metrics, external scheduler planner, worker dispatch, overlap prevention, ruleset pinning, snapshots, change suppression, and exception expiry. | Five offline scheduled-flow and worker-dispatch tests. | PASS |

> **Hard boundary:** Phase 5 stops at EX360-T052. The repository must not add generic relationships, multi-hop traversal, attack-paths, risk scores, exploitability, or remediation during this delivery.

## Durable Evaluation Operating Model

The worker’s `scheduler_heartbeat` task has no embedded beat configuration. A managed external scheduler invokes it, and the task uses the configured UTC interval fields `EXPOSURE_EVALUATION_INTERVAL`, `SNAPSHOT_INTERVAL`, `CHANGE_DETECTION_INTERVAL`, and `EXCEPTION_EXPIRY_INTERVAL` to enqueue only due active-organization jobs. Each queued job carries stable organization/type/correlation identifiers, creates an `evaluation_runs` record, and prevents duplicate same-type `RUNNING` runs within one organization.

| Run type | Persisted output | Safety control |
|---|---|---|
| `EXPOSURE_RULE_EVALUATION` | Finding match/update events and evidence links. | One immutable ruleset hash is pinned per run; metadata-only evaluation makes no network call. |
| `ASSET_SNAPSHOT_BUILD` | Stable snapshots only when structural state differs. | Comparison projection excludes volatile display time. |
| `CHANGE_DETECTION` | Deterministic change events, score factors, and optional EXPECTED linkage. | Previous/current stored snapshots are compared; change events are retained. |
| `EXCEPTION_EXPIRY` | Reopened findings and system audit events. | No finding is deleted or closed by expiry. |

## Validation State

The current local cumulative backend gate passed **238 tests** with Ruff, formatter, and strict mypy. The cumulative frontend gate passed typecheck, lint, five Vitest suites with **16 tests**, a Chromium Playwright scenario, and a production build. AWS upgraded from `0010_fingerprint_confidence` to `0017_evaluation_runs (head)`; the deployed self-cleaning fixture returned seven API HTTP 200 responses, passed scheduled exception expiry, and was verified absent after cleanup. GitHub pull request publication and archive hash evidence remain delivery controls.
