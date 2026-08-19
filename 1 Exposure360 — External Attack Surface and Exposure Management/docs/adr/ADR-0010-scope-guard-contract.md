# ADR-0010: Scope Guard Contract

Future connectors must use `ScopeGuard` and a guarded transport wrapper. The guard validates authorization, scope state, stop state, approval/hash, target inclusion/exclusion, protocol, schedule, and budgets before any transport call. Ambiguity and dependency failure deny by default.
