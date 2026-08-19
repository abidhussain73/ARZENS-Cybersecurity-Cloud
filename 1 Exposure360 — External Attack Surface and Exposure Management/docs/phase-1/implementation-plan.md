# Exposure360 Strict Phase 1 Implementation Plan

## Boundary and operating rule

This package implements **only Phase 1 through EX360-T010**. The schema remains limited to users, organizations, memberships, and audit events; no discovery, scope, asset, finding, risk, reporting, or remediation behavior is introduced.

| Requirement | Current assessment | Minimum action | Required evidence |
|---|---|---|---|
| EX360-T001 | Partial | Add manual branch-protection record; verify repository governance artifacts. | Clone and file/CI checks; manual remote setting record. |
| EX360-T002 | Partial | Add `uv.lock`; correct quality issues; execute backend quality suite. | Ruff, format, mypy, pytest pass. |
| EX360-T003 | Partial | Pin frontend dependencies; add lock, tests, and Playwright shell coverage. | Lint, typecheck, unit tests, build, E2E pass. |
| EX360-T004 | Partial | Complete the nine-service health matrix, including object-store mutation and worker/scheduler proof. | Valid Compose config and complete runtime checks. |
| EX360-T005 | Partial | Add startup-validation negative tests with safe error checks. | Missing/malformed configuration fails without secret disclosure. |
| EX360-T006 | Pass (migration) | Preserve migration baseline and add repository integration coverage. | Empty database migrates to `0001_phase1_foundation`. |
| EX360-T007 | Not accepted | Replace test-subject header authentication with OIDC discovery/JWKS validation and idempotent bootstrap. | 401 unauthenticated; valid Keycloak `/me` 200; no duplicate profile. |
| EX360-T008 | Not accepted | Seed ORG-A/ORG-B users and verify server-side membership isolation. | Authorized context succeeds; cross-org attempt is 403. |
| EX360-T009 | Not accepted | Strengthen privileged membership audit evidence and transaction linkage. | Matching audit actor, org, action, and correlation ID. |
| EX360-T010 | Not accepted | Add end-to-end trace context, JSON logs/redaction, worker handoff, and metric proof. | Correlation/trace spans and metrics demonstrate API-to-worker flow. |

## Controlled sequence

The implementation sequence is authentication and test fixtures first, then organization isolation and auditing, then observability and full quality/health validation. Each claimed task status must be backed by command output or deterministic automated tests in `docs/phase-1/test-evidence.md`. Remote deployment receives updates only after the corresponding local validation passes.
