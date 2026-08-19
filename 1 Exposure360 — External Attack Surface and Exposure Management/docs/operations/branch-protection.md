# Branch Protection for `main`

> **REMOTE ADMIN ACTION REQUIRED.** The isolated foundation repository is local-only at the time of this record, so remote branch protection cannot be configured or claimed as active.

When the repository is hosted, a repository administrator must configure the default branch `main` with the following protections before team handoff.

| Setting | Required value |
|---|---|
| Pull request requirement | Enabled for all changes to `main`. |
| Review requirement | At least one approving review. |
| Stale approvals | Dismiss when new commits are pushed. |
| Required checks | `backend-quality`, `frontend-quality`, and `compose-config` from `.github/workflows/ci.yml`. |
| Direct pushes | Blocked, including for administrators unless a documented emergency process is approved. |
| Force pushes | Blocked. |
| Branch deletion | Blocked. |
| Code-owner review | Require review where the hosting provider supports CODEOWNERS enforcement. |

The repository-side `.github/CODEOWNERS` file and CI workflow are present. This document records the remaining administrative action without representing it as completed.
