# Phase 7 Risk Factor Registry

Registry version: `risk-factor-registry-v1`. The configured factors deliberately use data already modeled by Exposure360.

| Key | Weight | Purpose |
|---|---:|---|
| FINDING_SEVERITY | 0.30 | Rule severity context |
| FINDING_CONFIDENCE | 0.15 | Evidence confidence from the finding |
| EXTERNAL_SERVICE_EXPOSURE | 0.15 | Current external service context |
| ATTACK_PATH_SCORE | 0.20 | Phase 6 analytical topology score |
| ATTACK_PATH_CONFIDENCE | 0.10 | Confidence in bounded path context |
| VULNERABILITY_CONTEXT | 0.10 | Current imported relationship context only |

Every API detail response lists raw value, normalized value, configured/effective weight, contribution, availability, confidence, reason code, and non-secret evidence reference.
