# ADR 006 — Remediation State Machine

## Decision

Use named explicit transition actions and prohibit generic state patches.

## Rationale

The transition map preserves auditability and prevents a task from being manually marked verified or closed.
