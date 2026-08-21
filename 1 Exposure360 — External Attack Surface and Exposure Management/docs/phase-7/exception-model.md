# Exception Model

Risk acceptance exceptions begin in `REQUESTED`; reviewers, administrators, or owners may approve or reject them, while revocation is restricted to administrators or owners. Exceptions contain rationale, UTC request/approval/expiry/revocation timestamps, related finding/task context, and tenant scope.

An exception can change workflow or SLA handling but never deletes the finding, risk assessment, evidence, or verification requirement. List and action endpoints are organization-scoped and role-checked.
