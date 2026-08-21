# Phase 7 Risk Model

Exposure360 calculates **Raw Contextual Risk Score** and **Adjusted Contextual Risk Score** as deterministic prioritization values. They are not probabilities of compromise and do not establish exploitability.

Raw score uses only `AVAILABLE` factors, normalized to 0–100 by available configured weight. Missing, stale, and invalid applicable factors remain visible and reduce factor coverage and risk confidence; they do not become zero-risk inputs. The current model is `contextual-risk-v1` with `risk-factor-registry-v1`.

| Band | Range |
|---|---:|
| LOW | 0–19 |
| MODERATE | 20–39 |
| ELEVATED | 40–59 |
| HIGH | 60–79 |
| CRITICAL_PRIORITY | 80–100 |

Each stored assessment preserves its model version, registry hash, explanation, evaluation time, factor outputs, coverage, confidence, and risk band.
