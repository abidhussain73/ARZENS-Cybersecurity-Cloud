# API Examples

Phase 6 supplies internal bounded services rather than a public graph-dump API.

```python
result = traversal.traverse(
    organization_id,
    start_nodes=(start_node,),
    profile=EXPOSURE_TO_DATA,
    max_hops=4,
    effective_at=utc_time,
    max_paths=500,
    max_nodes=5000,
)
```

Returned paths must be presented as graph-theoretic context, not exploit verification.
