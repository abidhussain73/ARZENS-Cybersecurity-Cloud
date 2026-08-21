# Evidence-Based Closure Gate

The gate returns `ALLOW_CLOSE`, `DENY_CLOSE`, or `INCONCLUSIVE`. It allows closure only when the finding/task are pending verification, verification completed with `CONDITION_ABSENT`, evidence is current and integrity-valid, collection is complete, scope approval is valid, the correct rule/target was checked, and no contradictory current evidence exists.

`CONDITION_PRESENT` returns `DENY_CLOSE` and moves the task back to `IN_PROGRESS`. Missing, stale, incomplete, tampered, wrong-target, invalid-scope, or contradictory evidence returns `INCONCLUSIVE` and leaves the task/finding unclosed. Every completion creates an immutable closure-decision record.
