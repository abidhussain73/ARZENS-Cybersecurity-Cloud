# Phase 5 Implementation Plan

## Baseline

The merged Phase 4 protected-main baseline was verified before Phase 5 work began. The API quality gate passed with 185 tests. The current Phase 5 development increment also passes Ruff, formatter, strict mypy, and 204 backend tests. No Phase 6 capability is included.

## Completed, validated increment

| Task | Delivered foundation | Evidence |
|---|---|---|
| EX360-T042 | Organization-scoped Assets inventory/detail client and UI, server filters, pagination, evidence authorization action, history, and direct relationships | Frontend typecheck, lint, focused UI tests, and production build pass |
| EX360-T043 | Immutable versioned declarative exposure rules with safe fields/operators, bounded nesting, stable hashes, and activation validation | 8 offline loader/repository tests pass |
| EX360-T044 | Pure metadata-only evaluator for HSTS, certificate expiry, server version disclosure, and ownership absence | 4 fixture tests pass; evaluator has no transport imports |
| EX360-T045/T046 | Evidence-backed Finding lifecycle, audited transitions, deduplication, temporal updates, and recurrence handling | 5 constraint-enforcing SQLite tests pass |
| EX360-T047 | Canonical snapshot serializer and durable snapshot schema/repository foundation | 2 deterministic serialization tests pass |

## Remaining authoritative work

EX360-T047 persistence acceptance completion, EX360-T048 change detection, EX360-T049 approved-change suppression/significance, EX360-T050 APIs, EX360-T051 Findings/Changes UI, EX360-T052 metrics and durable scheduled evaluation remain pending. These tasks will be implemented and fully regressed before any AWS deployment, publication, archive creation, or Phase 6 transition.
