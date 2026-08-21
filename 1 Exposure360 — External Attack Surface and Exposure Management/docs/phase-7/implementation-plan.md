# Phase 7 Implementation Plan

## Baseline Verification

The merged Phase 1–6 baseline was checked on 2026-08-21 UTC. Ruff, formatting, and strict mypy passed; the backend regression suite completed with **261 passing tests**. Phase 7 work is isolated on `phase7-development` from protected-main revision `45094ca8d22d8fcadb726605ba1685cc99fdc797`.

## Delivery Sequence

| Task | Implementation focus | Boundary |
|---|---|---|
| EX360-T058 | Versioned factor registry, availability-aware raw contextual risk, confidence, and coverage | Missing factors never become zero risk |
| EX360-T059 | Evidence-backed verified controls and bounded, explainable adjusted contextual risk | Stale, invalid, expired, revoked, or cross-org controls reduce nothing |
| EX360-T060 | Remediation task, exception, SLA, state transitions, and event history | Work tracking only; no source-system action |
| EX360-T061 | Safe retest records and closure gate | Current authorized evidence is mandatory for closure |
| EX360-T062 | Organization-safe FastAPI APIs and OpenAPI evidence | Lists are bounded; no generic state patch or close bypass |
| EX360-T063 | Attack-path and remediation analyst workflow UI | No Phase 8 dashboard, search, reports, exports, webhooks, or notification center |

The contextual prioritization model is deterministic and descriptive. It does not represent probability of compromise or verified exploitability.
