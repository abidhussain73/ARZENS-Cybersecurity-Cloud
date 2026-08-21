# Phase 6 Implementation Plan

## Scope and boundary

Phase 6 implements only **EX360-T053 through EX360-T057**: time-aware relationships, synthetic provider-neutral context imports, bounded graph traversal, explainable attack-path analysis, and in-memory path-breaking simulation. It does not implement exploitability claims, source-system mutation, contextual risk, remediation tasks, retesting, or any Phase 7 capability.

## Baseline

The accepted Phase 1–5 baseline was rerun from protected `main` before Phase 6 work began. Ruff, formatter, strict mypy, and the backend suite passed with **238 tests**. Phase 6 is developed on the isolated `phase6-development` branch.

## Design decisions

| Concern | Decision |
|---|---|
| Node identity | Graph nodes are either canonical Exposure360 assets or bounded external-context entities; imported context never creates fake assets. |
| Relationship truth | Edges are directional, organization-scoped, type-allowlisted, evidence-backed, temporal, and deterministically identified. |
| Traversal | Application-level bounded traversal uses explicit profiles, allowed edges, organization filtering, per-path cycle prevention, and strict path/node/hop ceilings. |
| Scoring | Attack-Path Score is explainable topology context, not risk or proof of exploitability. |
| Candidate evaluation | Path-breaking candidates operate only on an in-memory graph projection and cannot modify a cloud, identity, network, DNS, or application source. |

## Evidence plan

Each task is validated with static checks, strict typing, constraint-enforcing SQLite tests, synthetic fixtures only, organization-isolation checks, deterministic outputs, and the authoritative acceptance matrix before the task ledger is marked complete.
