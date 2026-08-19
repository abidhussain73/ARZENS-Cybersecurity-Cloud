# ADR-0013: Candidate Confidence Is Versioned, Explained, and Not Authorization

## Status

Accepted.

## Context

Multiple passive source observations may associate a candidate with an approved scope. A raw count rewards provider replay and obscures why a candidate exists. Treating that score as permission or risk would violate the Phase 2 authorization boundary.

## Decision

Confidence model `candidate-confidence-v1` groups observations by independent evidence category and applies fixed bounded weights: recorded passive DNS `0.60`, certificate metadata `0.65`, current DNS validation `0.90`, and TCP reachability `0.70` for endpoint hints. The deterministic combination is `1 - product(1 - weight)` capped at `0.99`. Each candidate stores model version, score, and sorted factor explanation.

## Consequences

Duplicate observations from one category do not raise confidence. Replay is idempotent. New independent evidence changes the score predictably. Neither candidate confidence nor a candidate row authorizes a DNS, TCP, TLS, or HTTP transport call; only current ScopeGuard and policy evaluation do that.
