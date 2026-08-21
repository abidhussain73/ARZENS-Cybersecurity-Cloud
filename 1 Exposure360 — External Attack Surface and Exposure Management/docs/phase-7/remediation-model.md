# Remediation Model

`RemediationTask` records human-approved work only. It is not a source-system actuator. A task stores the related finding and asset, optional analytical path context, title/description, owner, state, priority, UTC timestamps, due date, immutable event history, versioned SLA instance, exceptions, verification runs, and closure decisions.

Task creation derives priority from the latest contextual risk band and requires a matching active SLA policy. The dashboard exposes explicit actions only; it does not offer a generic state patch or manual verified/closed action.
