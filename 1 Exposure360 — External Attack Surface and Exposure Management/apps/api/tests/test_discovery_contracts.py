from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from exposure360_api.discovery_contracts import (
    CandidateAssetContract,
    CandidateType,
    DiscoveryCheckpointContract,
    DiscoverySourceContract,
    DiscoverySourceType,
    DiscoveryStageName,
    SourceBatch,
    SourceRecordContract,
)
from exposure360_api.models import (
    CandidateAsset,
    CandidateObservation,
    CollectionAttempt,
    DeadLetterItem,
    DiscoveryCheckpoint,
    DiscoveryJob,
    DiscoveryJobEvent,
    DiscoveryJobStage,
    DiscoverySource,
)


def _candidate_payload() -> dict[str, object]:
    return {
        "organization_id": uuid4(),
        "scope_id": uuid4(),
        "scope_version_id": uuid4(),
        "scope_approval_id": uuid4(),
        "candidate_type": CandidateType.DOMAIN,
        "raw_value": "WWW.Example.COM.",
        "canonical_value": "www.example.com",
        "source_key": "fixture-passive-dns",
        "source_record_key": "record-001",
        "observed_at": datetime.now(UTC),
        "confidence_hint": 0.6,
        "metadata": {"rrtype": "A", "provider_payload": {"extra": "contained"}},
    }


def test_candidate_contract_accepts_governed_domain_and_ip_candidates() -> None:
    domain = CandidateAssetContract.model_validate(_candidate_payload())
    ip = CandidateAssetContract.model_validate(
        {
            **_candidate_payload(),
            "candidate_type": CandidateType.IP,
            "raw_value": "192.0.2.20",
            "canonical_value": "192.0.2.20",
        }
    )

    assert domain.candidate_type is CandidateType.DOMAIN
    assert ip.candidate_type is CandidateType.IP
    assert domain.metadata["rrtype"] == "A"


@pytest.mark.parametrize(
    "missing_field", ["organization_id", "scope_id", "scope_version_id", "scope_approval_id"]
)
def test_candidate_contract_requires_organization_and_approved_scope_references(
    missing_field: str,
) -> None:
    payload = _candidate_payload()
    payload.pop(missing_field)

    with pytest.raises(ValidationError):
        CandidateAssetContract.model_validate(payload)


def test_candidate_contract_rejects_malformed_values_unexpected_fields_and_naive_timestamps() -> (
    None
):
    malformed = {**_candidate_payload(), "canonical_value": ""}
    unexpected = {**_candidate_payload(), "provider_private_field": "must-not-cross-contract"}
    naive_time = {**_candidate_payload(), "observed_at": datetime(2026, 1, 1)}

    for payload in (malformed, unexpected, naive_time):
        with pytest.raises(ValidationError):
            CandidateAssetContract.model_validate(payload)


def test_source_batch_and_checkpoint_round_trip_with_timezone_aware_timestamps() -> None:
    checkpoint = DiscoveryCheckpointContract(
        source_key="fixture-passive-dns",
        adapter_version="1.0.0",
        stage=DiscoveryStageName.PASSIVE_SOURCE,
        token={"record_index": 2},
    )
    batch = SourceBatch(
        records=[
            SourceRecordContract(
                source_record_key="passive-001",
                payload_hash="a" * 64,
                observed_at=datetime.now(UTC),
                attributes={"rrname": "www.example.com"},
            )
        ],
        next_checkpoint=checkpoint,
        source_observed_at=datetime.now(UTC),
        retrieved_at=datetime.now(UTC),
    )

    decoded = SourceBatch.model_validate_json(batch.model_dump_json())

    assert decoded.next_checkpoint is not None
    assert decoded.next_checkpoint.token == {"record_index": 2}
    assert decoded.records[0].observed_at.tzinfo is not None


def test_source_contract_rejects_unsupported_source_enum() -> None:
    payload = {
        "organization_id": uuid4(),
        "source_key": "fixture-passive-dns",
        "source_type": DiscoverySourceType.RECORDED_PASSIVE_DNS,
        "display_name": "Recorded Passive DNS",
        "adapter_version": "1.0.0",
    }
    source = DiscoverySourceContract.model_validate(payload)

    assert source.source_type is DiscoverySourceType.RECORDED_PASSIVE_DNS
    with pytest.raises(ValidationError):
        DiscoverySourceContract.model_validate({**payload, "source_type": "UNSUPPORTED"})


def test_phase_three_staging_entities_are_organization_owned_and_constrained() -> None:
    models = (
        DiscoverySource,
        DiscoveryJob,
        DiscoveryJobStage,
        DiscoveryCheckpoint,
        CandidateAsset,
        CandidateObservation,
        CollectionAttempt,
        DiscoveryJobEvent,
        DeadLetterItem,
    )

    for model in models:
        assert "organization_id" in model.__table__.c

    candidate_constraints = {constraint.name for constraint in CandidateAsset.__table__.constraints}
    source_constraints = {constraint.name for constraint in DiscoverySource.__table__.constraints}
    job_constraints = {constraint.name for constraint in DiscoveryJob.__table__.constraints}

    assert {"uq_candidate_asset_identity", "ck_candidate_asset_type"}.issubset(
        candidate_constraints
    )
    assert {"uq_discovery_source_org_key", "ck_discovery_source_type"}.issubset(source_constraints)
    assert {"fk_discovery_job_scope_version_org", "fk_discovery_job_approval_org"}.issubset(
        job_constraints
    )
