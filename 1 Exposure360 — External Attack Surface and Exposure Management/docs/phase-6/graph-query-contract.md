# Graph Query Contract

`GraphTraversalService.traverse()` needs an authorized organization/start node, named profile, effective time, and bounded limits. It returns simple paths, visited-node count, truncation state, and warnings.

| Limit | Ceiling |
|---|---:|
| Hops | 6 |
| Paths | 500 |
| Nodes | 5,000 |

Every query uses explicit allowed edges; no unbounded graph dump is exposed.
