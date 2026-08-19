# Scope Semantics

## Canonical Targets

Domain seeds are DNS names, not URLs. The normalizer trims legal outer whitespace, rejects controls and embedded NULs, converts Unicode to IDNA ASCII, removes one trailing DNS dot, lowercases, and validates labels. Wildcards are not accepted; domain matching is explicit: `EXACT` means equality, while `DOMAIN_AND_SUBDOMAINS` means equality or a `.` label boundary before the canonical seed.

CIDR parsing uses Python `ipaddress` with host-bit normalization. Exact IP inputs become `/32` or `/128`; global catch-all networks are rejected. ASN input accepts numeric or `AS`-prefixed notation and canonicalizes to `AS<number>` within unsigned 32-bit range. Raw input and canonical value are both retained for review.

## Inclusion, Exclusion, and Conflicts

Authorization requires a target to be included and not excluded. `EXCLUSION > INCLUSION` without exception. Duplicate or redundant seeds are blocking configuration errors; an exclusion outside every inclusion is a warning retained for operator review. Exact and subtree domain semantics are never inferred by string suffix alone.

## Approval and Execution

Draft versions can be edited. Submitted versions are content-hashed and become eligible for approval. Approval is an immutable record that references an exact scope version and hash. An approved version becomes the sole active version only transactionally; superseded versions and approvals remain historical. A future execution envelope must carry organization, scope, version, approval, and policy hash.
