# Temporal Semantics

`first_seen` and `last_seen` are observation times; `valid_from` and `valid_to` are effective validity. An edge is active at `t` when `valid_from <= t` and `valid_to` is absent or `t < valid_to`. Ending an edge retains history and supports historical analysis.
