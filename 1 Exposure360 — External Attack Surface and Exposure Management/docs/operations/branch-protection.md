# Branch Protection for `main`

> **REMOTE CONFIGURATION VERIFIED.** On 2026-08-19T09:39:22Z, the public repository [`abidhussain73/ARZENS-Cybersecurity-Cloud`](https://github.com/abidhussain73/ARZENS-Cybersecurity-Cloud) was configured with the protections below. Exposure360 Phase 1 is located in `1 Exposure360 — External Attack Surface and Exposure Management/`.

The default branch `main` is protected with the following controls.

| Setting | Required value |
|---|---|
| Pull request requirement | Enabled for all changes to `main`. |
| Review requirement | At least one approving review. |
| Stale approvals | Dismiss when new commits are pushed. |
| Required checks | `backend-quality`, `frontend-quality`, and `compose-config` from the root `.github/workflows/phase1-quality.yml`. The initial hosted run `32237622635` completed successfully. |
| Direct pushes | Blocked, including for administrators unless a documented emergency process is approved. |
| Force pushes | Blocked. |
| Branch deletion | Blocked. |
| Code-owner review | Require review where the hosting provider supports CODEOWNERS enforcement. |

The root `.github/CODEOWNERS` assigns the repository owner to the project folder and governance metadata. Temporary pull request [#1](https://github.com/abidhussain73/ARZENS-Cybersecurity-Cloud/pull/1) completed all required quality checks and remained `BLOCKED` with `REVIEW_REQUIRED` until it was closed without merge, demonstrating review enforcement. Force pushes and branch deletion are disabled in the verified policy.
