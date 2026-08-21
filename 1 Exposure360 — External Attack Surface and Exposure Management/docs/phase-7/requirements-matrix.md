# Phase 7 Requirements Matrix

| Task | Authoritative requirement | Current evidence status |
|---|---|---|
| EX360-T058 | Factor-availability-aware contextual risk scoring | Local code and tests complete — deterministic scorer, persistence, factor API explanation, documentation, and tenant coverage; AWS deployment evidence pending. |
| EX360-T059 | Verified-control reduction with freshness and confidence | Local code and tests complete — persisted evidence, stale/revoked zero-reduction, API truth labels, and documentation; AWS deployment evidence pending. |
| EX360-T060 | Remediation task, exception, and SLA models | Local code and tests complete — state machine, audited task/finding synchronization, versioned SLA, exception lifecycle, task detail/actions; AWS deployment evidence pending. |
| EX360-T061 | Retest workflow and current-evidence closure gate | Local code and tests complete — immutable verification/closure records, ScopeGuard-backed retest request, inconclusive-denial and verified-closure contracts; AWS deployment evidence pending. |
| EX360-T062 | Organization-safe attack-path, risk, and remediation APIs | Local code and integration matrix complete — bounded endpoints, isolation/RBAC, invalid transition, pagination, OpenAPI, and closure decision detail; AWS endpoint evidence pending. |
| EX360-T063 | Attack Paths and Remediation UI with workflow evidence | Integration-ready dashboard code complete — authenticated PKCE gateway client, API-backed loading/error/empty states, safety labels and action forms; public TLS/DNS activation and signed-in E2E workflow pending. |

> **Phase 7 terminology:** use **Raw Contextual Risk Score**, **Adjusted Contextual Risk Score**, **Risk Confidence**, **Factor Coverage**, and **Verified Control Reduction**. An attack path remains analytical context, not a verified exploit chain.

> **Hard boundary:** stop at EX360-T063. Do not build Phase 8 dashboard, search, reporting, export, webhook, connector-management, notification-center, or platform-wide accessibility capabilities.

> **Current local evidence:** the backend quality gate passes with **298 tests** when local trace export is disabled because the sandbox lacks a local OTLP collector. Managed-dashboard TypeScript checks, 13 unit tests, and production build pass. Caddy and compose configuration validated privately on AWS without replacing the existing Phase 6 deployment. This remains incremental evidence, not Phase 7 acceptance.
