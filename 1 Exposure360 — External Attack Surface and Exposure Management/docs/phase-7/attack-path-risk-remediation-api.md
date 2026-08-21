# Attack Path, Risk, and Remediation API

All Phase 7 routes are under `/api/v1`, use OIDC bearer authentication, require an authorized organization context, enforce role checks for mutation, and bound list sizes. Attack paths are explicitly `analytical_only=true` and `exploitability_verified=false`; path-breaking is `simulation_only=true` and `source_system_mutation=false`.

The API provides bounded attack-path list/analysis/candidates, contextual-risk list/detail/latest finding risk, policy-backed remediation task create/list/detail/actions/SLA, exception lifecycle, ScopeGuard-backed retest, verification-run listing/detail, and OpenAPI routes. There is no close-without-verification endpoint.
