# Security Test Plan

Phase 6 tests use SQLite and deterministic fixtures only. They cover endpoint XOR, type/kind rejection, cross-org boundaries, import tenancy, cycles, self-loops, temporal filters, confidence filters, truncation, and no-mutation candidate evaluation.

No test performs active network scanning, exploitation, credential use, or source-system mutation.
