# Phase 2 Scope Governance Data Model

| Entity | Ownership and identity | Purpose | Immutability / constraints |
|---|---|---|---|
| Scope | Organization-owned stable boundary | Holds business name, status, active version pointer | Disabled and archived state are separate from approval state |
| ScopeVersion | Scope and organization-owned numbered revision | Holds version state, content hash, creator, supersession link | Approved content is immutable; `(scope_id, version_number)` unique |
| ScopeSeed | Scope-version and organization-owned normalized inclusion | DOMAIN, CIDR, IP, or ASN with raw/canonical value and match mode | Draft-only modification; canonical uniqueness per type/version |
| ScopeExclusion | Scope-version and organization-owned normalized denial | Overrides inclusion for an exact target or subtree/network | Draft-only modification; exclusion always wins |
| ScanPolicy | One policy per version | Protocols, conservative rate/concurrency limits, IANA timezone, windows, timeouts | Positive bounded limits and validated policy structure |
| ScopeApproval | Exact immutable decision for one submitted version | Stores approver, content hash, decision, optional expiry | Approved record is never edited or re-used for another version |
| EmergencyStopState | Organization or scope level state | Fast, auditable stop generation and reason | Organization stop takes precedence; resume never restarts work |

Every entity stores its `organization_id` and is linked through foreign keys. Repository queries must filter organization and resource identifiers together; a body field can never select an organization.
