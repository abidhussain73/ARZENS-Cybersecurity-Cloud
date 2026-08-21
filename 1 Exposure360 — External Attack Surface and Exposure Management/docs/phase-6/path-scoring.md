# Attack-Path Scoring

`attack-path-score-v1` produces a 0–100 **Attack-Path Score**, not a risk score. It provides explicit factors and excludes Phase 7 criticality, control reduction, remediation, and exploitability assumptions.

| Factor | Points |
|---|---:|
| External start | +20 |
| High/critical active finding | +15 |
| Medium active finding | +8 |
| Vulnerability context | +10 |
| Identity administration | +18 |
| Data destination | +15 |
| Each additional hop | -5 |
