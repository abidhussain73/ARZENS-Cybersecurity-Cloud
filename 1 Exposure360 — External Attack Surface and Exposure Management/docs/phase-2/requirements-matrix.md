# Phase 2 Requirements Matrix

| Task | Requirement | Existing implementation | Gap | Planned modules | Tests and evidence | Status |
|---|---|---|---|---|---|---|
| EX360-T011 | Scope governance model | Phase 1 has orgs, users, memberships, audit | No scope entities | models, migration, repositories | migration and constraints | PENDING |
| EX360-T012 | Normalize domain, CIDR, ASN | No target parser | No canonical target contract | normalization service | unit boundary matrix | PENDING |
| EX360-T013 | Exclusion precedence and conflicts | No analyzer | No overlap policy | conflict service | unit conflict matrix | PENDING |
| EX360-T014 | Approval and active version | Phase 1 audit/RBAC available | No immutable authorization | approval service | unit/integration/race tests | PENDING |
| EX360-T015 | Protocol/rate/schedule/concurrency policy | Redis/Celery foundation available | No policy evaluator | policy service/settings | deterministic policy tests | PENDING |
| EX360-T016 | Emergency stop | Worker infrastructure available | No stop state/cancellation contract | stop service/worker test task | security and fake-running tests | PENDING |
| EX360-T017 | Governance API | `/api/v1`, OIDC, org context available | No scope routes/schemas | routes/schemas/repositories | integration/OpenAPI snapshot | PENDING |
| EX360-T018 | Scope administration UI | Phase 1 React shell available | No routing/editor/flow | React scope components | RTL and Playwright | PENDING |
| EX360-T019 | Central scope guard | OTel and worker available | No pre-transport guard | guard/guarded transport | zero-call denial tests | PENDING |
| EX360-T020 | Scope lifecycle audit | Generic writer exists | No scope action coverage | audit integration | correlated audit tests | PENDING |
