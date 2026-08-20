"""Metadata-only durable Phase 5 evaluation flows invoked by worker tasks."""

import uuid
from datetime import UTC, datetime
from typing import Final

from sqlalchemy import select
from sqlalchemy.orm import Session

from .approved_changes import SignificanceScorer
from .asset_snapshots import AssetSnapshotBuilder, AssetSnapshotInput, AssetSnapshotRepository
from .change_detector import ChangeDetector, ChangeEventRepository
from .evaluation_scheduler import EvaluationMetrics
from .exposure_evaluator import ExposureFactSet, ExposureRuleEvaluator
from .exposure_rules import ExposureRuleset
from .findings import FindingFingerprintService, FindingMatch, FindingService
from .models import (
    ApprovedChange,
    Asset,
    AssetOwnership,
    AssetSnapshot,
    AuditEvent,
    CanonicalObservation,
    ChangeEvent,
    EvaluationRun,
    Evidence,
    Finding,
    ServiceAsset,
    TechnologyFingerprint,
)

_RUN_TYPES: Final[frozenset[str]] = frozenset(
    {"EXPOSURE_RULE_EVALUATION", "ASSET_SNAPSHOT_BUILD", "CHANGE_DETECTION", "EXCEPTION_EXPIRY"}
)


class ScheduledEvaluationService:
    """Runs one persisted evaluation type using only stored canonical metadata."""

    def __init__(self, session: Session):
        self._session = session

    def execute(
        self,
        run: EvaluationRun,
        *,
        now: datetime | None = None,
        ruleset: ExposureRuleset | None = None,
    ) -> EvaluationMetrics:
        when = _utc(now or datetime.now(tz=UTC))
        if run.run_type not in _RUN_TYPES:
            raise ValueError("unsupported evaluation run type")
        if run.run_type == "ASSET_SNAPSHOT_BUILD":
            return self._build_snapshots(run, when)
        if run.run_type == "CHANGE_DETECTION":
            return self._detect_changes(run, when)
        if run.run_type == "EXCEPTION_EXPIRY":
            return self._expire_exceptions(run, when)
        if ruleset is None:
            raise ValueError("exposure rule evaluation requires one pinned ruleset")
        return self._evaluate_rules(run, ruleset, when)

    def _build_snapshots(self, run: EvaluationRun, when: datetime) -> EvaluationMetrics:
        builder = AssetSnapshotBuilder()
        repository = AssetSnapshotRepository(self._session)
        assets = list(
            self._session.scalars(
                select(Asset)
                .where(Asset.organization_id == run.organization_id)
                .order_by(Asset.canonical_key)
            )
        )
        created = 0
        for asset in assets:
            snapshot = builder.build(self._snapshot_input(asset, when))
            latest = self._session.scalar(
                select(AssetSnapshot)
                .where(
                    AssetSnapshot.organization_id == run.organization_id,
                    AssetSnapshot.asset_id == asset.id,
                )
                .order_by(AssetSnapshot.effective_at.desc(), AssetSnapshot.id.desc())
            )
            if latest is not None and latest.snapshot_hash == snapshot.snapshot_hash:
                continue
            repository.persist(
                run.organization_id,
                asset.id,
                when,
                snapshot,
                source_evaluation_run_id=run.id,
            )
            created += 1
        return EvaluationMetrics(assets_processed=len(assets), snapshots_created=created)

    def _detect_changes(self, run: EvaluationRun, when: datetime) -> EvaluationMetrics:
        detector = ChangeDetector()
        repository = ChangeEventRepository(self._session)
        assets = list(
            self._session.scalars(
                select(Asset)
                .where(Asset.organization_id == run.organization_id)
                .order_by(Asset.canonical_key)
            )
        )
        created = 0
        suppressed = 0
        for asset in assets:
            snapshots = list(
                self._session.scalars(
                    select(AssetSnapshot)
                    .where(
                        AssetSnapshot.organization_id == run.organization_id,
                        AssetSnapshot.asset_id == asset.id,
                    )
                    .order_by(AssetSnapshot.effective_at.desc(), AssetSnapshot.id.desc())
                    .limit(2)
                )
            )
            if len(snapshots) < 2:
                continue
            current, previous = snapshots
            for detected in detector.compare(previous.snapshot_json, current.snapshot_json):
                existing = self._existing_change(
                    run.organization_id, asset.id, detected.change_type
                )
                event = repository.persist(
                    run.organization_id,
                    asset.id,
                    detected,
                    when,
                    from_snapshot_id=previous.id,
                    to_snapshot_id=current.id,
                )
                if existing is None:
                    created += 1
                if self._apply_expected_change(run, event, when):
                    suppressed += 1
        return EvaluationMetrics(
            assets_processed=len(assets),
            changes_created=created,
            changes_suppressed=suppressed,
        )

    def _expire_exceptions(self, run: EvaluationRun, when: datetime) -> EvaluationMetrics:
        reopened = FindingService(self._session).reopen_expired_exceptions(
            run.organization_id,
            when,
            run.correlation_id,
        )
        for finding in reopened:
            self._session.add(
                AuditEvent(
                    organization_id=run.organization_id,
                    actor_user_id=None,
                    action="finding.exception_expired",
                    resource_type="finding",
                    resource_id=str(finding.id),
                    correlation_id=run.correlation_id,
                    trace_id=run.trace_id,
                    result="SUCCESS",
                    metadata_json={"run_id": str(run.id), "state": "OPEN"},
                )
            )
        return EvaluationMetrics(findings_updated=len(reopened))

    def _evaluate_rules(
        self, run: EvaluationRun, ruleset: ExposureRuleset, when: datetime
    ) -> EvaluationMetrics:
        evaluator = ExposureRuleEvaluator()
        finding_service = FindingService(self._session)
        rules = {item.rule_id: item for item in ruleset.rules if item.activation_state == "ACTIVE"}
        observations = list(
            self._session.scalars(
                select(CanonicalObservation)
                .where(
                    CanonicalObservation.organization_id == run.organization_id,
                    CanonicalObservation.state == "ACCEPTED",
                )
                .order_by(CanonicalObservation.asset_id, CanonicalObservation.observed_at)
            )
        )
        processed_assets: set[uuid.UUID] = set()
        created = 0
        updated = 0
        matched = 0
        for observation in observations:
            asset = self._session.scalar(
                select(Asset).where(
                    Asset.id == observation.asset_id,
                    Asset.organization_id == run.organization_id,
                )
            )
            if asset is None:
                continue
            processed_assets.add(asset.id)
            evidence_ids = tuple(
                self._session.scalars(
                    select(Evidence.id).where(
                        Evidence.organization_id == run.organization_id,
                        Evidence.observation_id == observation.id,
                    )
                )
            )
            facts = ExposureFactSet(
                asset_type=asset.asset_type,
                observation_type=observation.observation_type,
                values=self._fact_values(asset, observation, when),
                observation_id=str(observation.id),
                evidence_ids=tuple(str(item) for item in evidence_ids),
            )
            for result in evaluator.evaluate(facts, ruleset, when):
                if result.state != "MATCHED" or result.rule_id not in rules:
                    continue
                matched += 1
                rule = rules[result.rule_id]
                match = FindingMatch(
                    asset_id=asset.id,
                    service_asset_id=asset.id if asset.asset_type == "SERVICE" else None,
                    rule_id=result.rule_id,
                    rule_version=result.rule_version,
                    rule_hash=result.rule_hash,
                    title=rule.title,
                    description=rule.description,
                    category=rule.category,
                    rule_severity=result.severity,
                    confidence=result.confidence,
                    observed_at=observation.observed_at,
                    component_key=observation.observation_type,
                    observation_id=observation.id,
                    evidence_ids=evidence_ids,
                    evaluation_run_id=run.id,
                )
                fingerprint = FindingFingerprintService.create(run.organization_id, match)
                prior = self._session.scalar(
                    select(Finding.id).where(
                        Finding.organization_id == run.organization_id,
                        Finding.fingerprint == fingerprint,
                    )
                )
                finding_service.record_match(run.organization_id, match)
                if prior is None:
                    created += 1
                else:
                    updated += 1
        return EvaluationMetrics(
            assets_processed=len(processed_assets),
            findings_matched=matched,
            findings_created=created,
            findings_updated=updated,
        )

    def _snapshot_input(self, asset: Asset, now: datetime) -> AssetSnapshotInput:
        ownership = list(
            self._session.scalars(
                select(AssetOwnership).where(
                    AssetOwnership.organization_id == asset.organization_id,
                    AssetOwnership.asset_id == asset.id,
                    AssetOwnership.valid_from <= now,
                    (AssetOwnership.valid_to.is_(None)) | (AssetOwnership.valid_to > now),
                )
            )
        )
        primary = next((item for item in ownership if item.is_primary), None)
        service = self._session.scalar(
            select(ServiceAsset).where(
                ServiceAsset.organization_id == asset.organization_id,
                ServiceAsset.asset_id == asset.id,
            )
        )
        technologies = list(
            self._session.scalars(
                select(TechnologyFingerprint).where(
                    TechnologyFingerprint.organization_id == asset.organization_id,
                    TechnologyFingerprint.asset_id == asset.id,
                )
            )
        )
        services: tuple[dict[str, object], ...] = ()
        if service is not None:
            services = (
                {
                    "service_key": service.service_key,
                    "service_kind": service.service_kind,
                    "application_protocol": service.application_protocol,
                },
            )
        return AssetSnapshotInput(
            asset_type=asset.asset_type,
            canonical_key=asset.canonical_key,
            lifecycle_state=asset.lifecycle_state,
            display_last_seen=asset.last_seen,
            ownership={
                "primary_present": primary is not None,
                "primary": primary.owner_reference if primary else None,
                "conflict": len([item for item in ownership if item.is_primary]) > 1,
            },
            resolved_ips=(),
            services=services,
            technologies=tuple(
                {
                    "product": item.technology_product,
                    "version_value": item.version_value,
                    "category": item.technology_category,
                }
                for item in technologies
            ),
        )

    def _fact_values(
        self, asset: Asset, observation: CanonicalObservation, now: datetime
    ) -> dict[str, str | int | float | bool | datetime | None]:
        values: dict[str, str | int | float | bool | datetime | None] = {
            "asset.asset_type": asset.asset_type,
            "asset.lifecycle_state": asset.lifecycle_state,
            "ownership.primary_present": self._primary_owner_exists(asset.id, now),
            "ownership.conflict": False,
        }
        _flatten(observation.normalized_payload_json, "", values)
        prefix = "http" if observation.observation_type == "HTTP_RESPONSE" else "tls"
        _flatten(observation.normalized_payload_json, prefix, values)
        service = self._session.scalar(
            select(ServiceAsset).where(
                ServiceAsset.organization_id == asset.organization_id,
                ServiceAsset.asset_id == asset.id,
            )
        )
        if service is not None:
            values["service.application_protocol"] = service.application_protocol
            values["service.service_kind"] = service.service_kind
        return values

    def _primary_owner_exists(self, asset_id: uuid.UUID, now: datetime) -> bool:
        return (
            self._session.scalar(
                select(AssetOwnership.id).where(
                    AssetOwnership.asset_id == asset_id,
                    AssetOwnership.is_primary.is_(True),
                    AssetOwnership.valid_from <= now,
                    (AssetOwnership.valid_to.is_(None)) | (AssetOwnership.valid_to > now),
                )
            )
            is not None
        )

    def _existing_change(
        self, organization_id: uuid.UUID, asset_id: uuid.UUID, change_type: str
    ) -> ChangeEvent | None:
        return self._session.scalar(
            select(ChangeEvent).where(
                ChangeEvent.organization_id == organization_id,
                ChangeEvent.asset_id == asset_id,
                ChangeEvent.change_type == change_type,
            )
        )

    def _apply_expected_change(self, run: EvaluationRun, event: ChangeEvent, now: datetime) -> bool:
        approval = self._session.scalar(
            select(ApprovedChange).where(
                ApprovedChange.organization_id == run.organization_id,
                ApprovedChange.asset_id == event.asset_id,
                ApprovedChange.status == "ACTIVE",
                ApprovedChange.starts_at <= now,
                ApprovedChange.ends_at > now,
            )
        )
        if approval is None or event.change_type not in approval.allowed_change_types_json:
            SignificanceScorer().persist(event)
            return False
        component = approval.component_selector_json
        if component is not None and (
            component.get("component_key") != event.details_json.get("component_key")
        ):
            SignificanceScorer().persist(event)
            return False
        already_expected = event.approved_change_id == approval.id and event.state == "EXPECTED"
        event.approved_change_id = approval.id
        event.state = "EXPECTED"
        SignificanceScorer().persist(event)
        if not already_expected:
            self._session.add(
                AuditEvent(
                    organization_id=run.organization_id,
                    actor_user_id=None,
                    action="change_event.suppressed_expected",
                    resource_type="change_event",
                    resource_id=str(event.id),
                    correlation_id=run.correlation_id,
                    trace_id=run.trace_id,
                    result="SUCCESS",
                    metadata_json={
                        "approved_change_id": str(approval.id),
                        "change_type": event.change_type,
                    },
                )
            )
        return not already_expected


def _flatten(
    source: dict[str, object],
    prefix: str,
    target: dict[str, str | int | float | bool | datetime | None],
) -> None:
    for key, value in source.items():
        path = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            _flatten(value, path, target)
        elif isinstance(value, str | int | float | bool | datetime) or value is None:
            target[path.replace("-", "_")] = value


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
