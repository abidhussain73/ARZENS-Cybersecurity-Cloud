# Performance Test Plan

The implementation limits depth, paths, and nodes and batches adjacency by BFS frontier. Production-scale PostgreSQL acceptance should measure tenant-scoped indexed graph queries near configured ceilings, memory under truncation, and explicit partial result behavior.
