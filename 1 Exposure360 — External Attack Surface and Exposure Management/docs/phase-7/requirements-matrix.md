# Phase 7 Requirements Matrix

| Task | Authoritative requirement | Current evidence status |
|---|---|---|
| EX360-T058 | Factor-availability-aware contextual risk scoring | Partial — deterministic scorer, ORM persistence, SQLite tenant coverage, factor API explanation; final acceptance evidence pending. |
| EX360-T059 | Verified-control reduction with freshness and confidence | Partial — persisted evidence, stale/revoked zero-reduction tests, control API visibility; final acceptance evidence pending. |
| EX360-T060 | Remediation task, exception, and SLA models | Partial — state machine, persisted task/SLA/exception lifecycle, task-detail and explicit action APIs; final acceptance evidence pending. |
| EX360-T061 | Retest workflow and current-evidence closure gate | Partial — immutable verification/closure records, current-evidence gate, ScopeGuard-backed retest request; deployed acceptance pending. |
| EX360-T062 | Organization-safe attack-path, risk, and remediation APIs | Partial — bounded risk/task/exception/retest/attack-path APIs with isolation/RBAC contracts; remaining authoritative endpoint and integration matrix pending. |
| EX360-T063 | Attack Paths and Remediation UI with workflow evidence | Partial — managed dashboard fixture-preview routes, safety labels, unit/build and visual checks; live API binding and E2E workflow pending. |

> **Phase 7 terminology:** use **Raw Contextual Risk Score**, **Adjusted Contextual Risk Score**, **Risk Confidence**, **Factor Coverage**, and **Verified Control Reduction**. An attack path remains analytical context, not a verified exploit chain.

> **Hard boundary:** stop at EX360-T063. Do not build Phase 8 dashboard, search, reporting, export, webhook, connector-management, notification-center, or platform-wide accessibility capabilities.

> **Current branch evidence:** `phase7-development` at `5a77bb2`; the backend quality gate passes with 291 tests when local trace export is disabled because the sandbox lacks a local OTLP collector. This is incremental evidence only, not Phase 7 acceptance.
