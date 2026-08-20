import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from exposure360_api.certificate_source import RecordedCertificateMetadataAdapter
from exposure360_api.discovery_contracts import DiscoveryStageName, SourceRecordContract
from exposure360_api.discovery_sources import RecordedPassiveDnsAdapter, ScopeSourceContext
from exposure360_api.scope_governance import TargetRule

_FIXTURES = Path(__file__).parent / "fixtures"


def _records(name: str) -> list[dict[str, object]]:
    payload = json.loads((_FIXTURES / name).read_text(encoding="utf-8"))
    records = payload["records"]
    assert isinstance(records, list)
    return records


def _context() -> ScopeSourceContext:
    return ScopeSourceContext(
        organization_id=uuid4(),
        scope_id=uuid4(),
        scope_version_id=uuid4(),
        scope_approval_id=uuid4(),
        included_rules=(TargetRule("DOMAIN", "example.com", "DOMAIN_AND_SUBDOMAINS"),),
        exclusion_rules=(TargetRule("DOMAIN", "excluded.example.com", "EXACT"),),
    )


def test_recorded_passive_dns_adapter_has_stable_contract_pagination_and_health() -> None:
    adapter = RecordedPassiveDnsAdapter(
        _records("recorded_passive_dns.json"),
        page_size=2,
        clock=lambda: datetime(2026, 1, 15, tzinfo=UTC),
    )
    context = _context()

    first = adapter.collect(context, None)
    assert adapter.describe(context.organization_id).source_key == "fixture-passive-dns"
    assert adapter.capabilities().supports_checkpoint
    assert adapter.health().value == "HEALTHY"
    assert len(first.records) == 2
    assert first.next_checkpoint is not None
    assert first.next_checkpoint.token == {"record_index": 2}
    assert first.records[0].observed_at == datetime(2026, 1, 15, tzinfo=UTC)

    second = adapter.collect(context, first.next_checkpoint)
    assert len(second.records) == 1
    assert second.next_checkpoint is None


def test_recorded_passive_dns_adapter_emits_normalized_domain_and_ip_candidates() -> None:
    adapter = RecordedPassiveDnsAdapter(_records("recorded_passive_dns.json"))
    first_record = adapter.collect(_context(), None).records[0]

    result = adapter.normalize(_context(), first_record)

    assert [candidate.canonical_value for candidate in result.candidates] == [
        "www.example.com",
        "192.0.2.20/32",
    ]
    assert result.candidates[1].metadata["relationship_hint"] == "resolves_to"
    assert result.candidates[0].observed_at == datetime(2026, 1, 15, tzinfo=UTC)


def test_passive_adapter_rejects_out_of_scope_and_malformed_records() -> None:
    adapter = RecordedPassiveDnsAdapter(_records("recorded_passive_dns.json"))
    context = _context()
    out_of_scope = adapter.collect(context, None).next_checkpoint
    assert out_of_scope is not None
    record = adapter.collect(context, out_of_scope).records[0]

    assert adapter.normalize(context, record).warnings == ("OUT_OF_SCOPE_PASSIVE_DNS_RECORD",)
    malformed = SourceRecordContract(
        source_record_key="malformed",
        payload_hash="b" * 64,
        observed_at=datetime.now(UTC),
        attributes={"rrname": "www.example.com"},
    )
    assert adapter.normalize(context, malformed).warnings == ("MALFORMED_PASSIVE_DNS_RECORD",)


def test_recorded_certificate_adapter_extracts_sans_cn_and_safe_wildcard_base() -> None:
    adapter = RecordedCertificateMetadataAdapter(_records("recorded_certificate_metadata.json"))
    context = _context()
    batch = adapter.collect(context, None)

    result = adapter.normalize(context, batch.records[0])
    values = {candidate.canonical_value for candidate in result.candidates}

    assert values == {"www.example.com", "api.example.com", "example.com"}
    assert any(candidate.metadata["wildcard_hint"] for candidate in result.candidates)
    assert "OUT_OF_SCOPE_CERTIFICATE_DNS_NAME" in result.warnings
    assert "INVALID_CERTIFICATE_DNS_NAME" in result.warnings
    assert all("*." not in candidate.raw_value for candidate in result.candidates)


def test_recorded_certificate_adapter_preserves_timestamp_hash_and_cn_fallback() -> None:
    adapter = RecordedCertificateMetadataAdapter(_records("recorded_certificate_metadata.json"))
    context = _context()
    batch = adapter.collect(context, None)

    second = adapter.normalize(context, batch.records[1])
    assert [candidate.canonical_value for candidate in second.candidates] == ["portal.example.com"]
    assert second.candidates[0].observed_at == datetime(2026, 1, 16, tzinfo=UTC)
    assert len(batch.records[1].payload_hash) == 64
    assert batch.next_checkpoint is None
    assert adapter.collect(context, None).records[0].payload_hash == batch.records[0].payload_hash


def test_adapter_checkpoint_rejects_wrong_stage_or_source() -> None:
    adapter = RecordedPassiveDnsAdapter(_records("recorded_passive_dns.json"))
    checkpoint = adapter.collect(_context(), None).next_checkpoint
    assert checkpoint is not None
    wrong_stage = checkpoint.model_copy(update={"stage": DiscoveryStageName.CERTIFICATE_IMPORT})

    try:
        adapter.collect(_context(), wrong_stage)
    except ValueError as error:
        assert "Checkpoint" in str(error)
    else:
        raise AssertionError("Expected a checkpoint ownership error")
