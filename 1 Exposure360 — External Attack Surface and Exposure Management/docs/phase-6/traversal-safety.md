# Traversal Safety

The service uses bounded application BFS and batched per-frontier adjacency retrieval. Every relationship query filters by organization, effective time, profile allowlist, and optional minimum confidence. Per-path visited nodes prevent cycles while preserving valid diamond paths.

| Condition | Result |
|---|---|
| Cycle/self-loop | Repeated node skipped |
| Path cap | `PATH_LIMIT_REACHED`, partial result |
| Node cap | `NODE_LIMIT_REACHED`, partial result |
| Cross-org start | Rejected |
