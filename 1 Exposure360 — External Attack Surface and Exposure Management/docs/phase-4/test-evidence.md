# Phase 4 Test Evidence

The local Phase 4 quality gate completed on 2026-08-20 using the repository’s locked Python environment.

```text
cd apps/api
uv run ruff check .
uv run ruff format --check .
uv run mypy exposure360_api
uv run pytest -q
```

| Check | Verified result |
|---|---|
| Ruff lint | `All checks passed!` |
| Ruff formatting | `73 files already formatted` |
| Mypy strict | `Success: no issues found in 40 source files` |
| Pytest | `185 passed in 4.98s` |

Focused task suites also passed before this integrated gate: T036 ownership (3), T037 observation/evidence (3), T038 private store (3), T039 signatures (3), T040 evaluator (3), and T041 API contracts (3).

AWS evidence was then verified on the user-provided Ubuntu instance: Docker Compose rebuilt, Alembic reported `0010_fingerprint_confidence (head)`, and the self-cleaning Phase 4 fixture exercised list, detail, observations, evidence metadata, ownership, and direct relationships with HTTP 200 responses. The fixture did not perform active collection.
