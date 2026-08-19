# ADR-0009: Emergency Stop

Organization stop takes precedence over scope stop. Stop state has a monotonically increasing generation, is consulted immediately before each guarded operation, and is auditable. Resume permits new explicit work only and never restarts cancelled work.
