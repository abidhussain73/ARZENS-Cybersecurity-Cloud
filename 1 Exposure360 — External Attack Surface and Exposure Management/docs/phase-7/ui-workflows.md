# Phase 7 UI Workflows

The managed dashboard routes are `/attack-paths`, `/attack-paths/:analysisId`, `/remediation`, `/remediation/:taskId`, and `/exceptions`. They now contain no hardcoded Phase 7 fixture records. The browser client is integration-ready for the authenticated gateway: it uses Keycloak authorization-code flow with PKCE, holds access tokens only in session storage, sends bearer plus selected organization context, and renders loading, empty, and error states.

The dashboard shows analytical-only path warning, bounded details, candidate simulation context, contextual risk explanation, factor availability, verified-control truth labels, remediation history/SLA/closure decisions, governed exception actions, and scope-required retest inputs. The final external live connection remains deferred until the configured HTTPS hostname is available.
