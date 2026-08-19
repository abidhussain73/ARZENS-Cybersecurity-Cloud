# ADR-0007: Scope Approval Activation

Only submitted versions may be approved. An immutable approval stores the exact version content hash and optional expiry. Approval is transactional and leaves at most one active approved version per scope; the previous active version is superseded but retained.
