from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from exposure360_api.change_detector import ChangeDetector, ChangeEventRepository
from exposure360_api.db import Base
from exposure360_api.models import Asset, ChangeEvent, Organization

NOW = datetime(2026, 8, 20, tzinfo=UTC)


@pytest.fixture
def session() -> Session:
    engine = create_engine(
        "sqlite+pysqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection: object, _: object) -> None:
        connection.execute("PRAGMA foreign_keys=ON")  # type: ignore[union-attr]

    Base.metadata.create_all(engine)
    instance = sessionmaker(bind=engine, expire_on_commit=False)()
    try:
        yield instance
    finally:
        instance.close()
        engine.dispose()


def _asset(session: Session, name: str) -> Asset:
    organization = Organization(id=uuid4(), name=name, slug=f"{name}-{uuid4()}")
    asset = Asset(
        id=uuid4(),
        organization_id=organization.id,
        asset_type="DOMAIN",
        canonical_key=f"domain:{uuid4()}.example.test",
        display_name=name,
        first_seen=NOW,
        last_seen=NOW,
    )
    session.add(organization)
    session.commit()
    session.add(asset)
    session.commit()
    return asset


def _snapshot(
    *, services: object = (), ownership: object = "team:a", technologies: object = ()
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "asset": {"canonical_key": "domain:fixture.example.test"},
        "services": services,
        "ownership": ownership,
        "technologies": technologies,
    }


def test_identical_baseline_new_and_removed_snapshot_semantics() -> None:
    detector = ChangeDetector()
    current = _snapshot()
    assert detector.compare(current, current) == ()
    assert detector.compare(None, None) == ()
    assert detector.compare(None, current)[0].change_type == "NEW"
    assert detector.compare(current, None)[0].change_type == "REMOVED"


def test_service_ownership_and_fingerprint_changes_are_typed_and_deterministic() -> None:
    detector = ChangeDetector()
    previous = _snapshot(
        services=("https:443",), ownership="team:a", technologies=("FixtureWeb:1.2",)
    )
    current = _snapshot(
        services=("https:443", "https:8443"), ownership="team:b", technologies=("FixtureWeb:1.3",)
    )
    changes = detector.compare(previous, current)
    assert [change.change_type for change in changes] == ["OWNERSHIP", "FINGERPRINT", "SERVICE"]
    assert changes == detector.compare(previous, current)


def test_incompatible_snapshot_schema_is_never_compared() -> None:
    with pytest.raises(ValueError, match="incompatible"):
        ChangeDetector().compare(_snapshot(), {**_snapshot(), "schema_version": 2})


def test_certificate_rotation_is_a_certificate_change_not_a_service_change() -> None:
    previous = _snapshot(
        services=(
            {
                "protocol": "HTTPS",
                "endpoint": "tcp:192.0.2.20:443",
                "certificate_fingerprint": "old",
                "certificate_issuer": "Fixture CA",
            },
        )
    )
    current = _snapshot(
        services=(
            {
                "protocol": "HTTPS",
                "endpoint": "tcp:192.0.2.20:443",
                "certificate_fingerprint": "new",
                "certificate_issuer": "Fixture CA",
            },
        )
    )

    changes = ChangeDetector().compare(previous, current)

    assert [change.change_type for change in changes] == ["CERTIFICATE"]


def test_order_and_display_only_differences_produce_no_structural_change() -> None:
    previous = {
        **_snapshot(
            services=("tcp:443", "tcp:80"),
            technologies=("FixtureWeb:1.2", "FixtureProxy:2.0"),
        ),
        "display": {"last_seen": "2026-08-20T00:00:00+00:00"},
    }
    current = {
        **_snapshot(
            services=("tcp:80", "tcp:443"),
            technologies=("FixtureProxy:2.0", "FixtureWeb:1.2"),
        ),
        "display": {"last_seen": "2026-08-21T00:00:00+00:00"},
    }

    assert ChangeDetector().compare(previous, current) == ()


def test_required_two_snapshot_change_categories_are_typed() -> None:
    detector = ChangeDetector()
    baseline = _snapshot(
        services=("tcp:443",),
        ownership={"primary_owner": "team:a", "state": "RESOLVED"},
        technologies=("FixtureWeb:1.2",),
    )
    service_added = {**baseline, "services": ("tcp:443", "tcp:8443")}
    service_removed = {**service_added, "services": ("tcp:443",)}
    owner_changed = {
        **baseline,
        "ownership": {"primary_owner": "team:b", "state": "RESOLVED"},
    }
    owner_conflict = {
        **baseline,
        "ownership": {"primary_owner": "team:a", "state": "CONFLICT"},
    }
    fingerprint_changed = {**baseline, "technologies": ("FixtureWeb:1.3",)}

    assert detector.compare(None, baseline)[0].change_type == "NEW"
    assert detector.compare(baseline, None)[0].change_type == "REMOVED"
    assert detector.compare(baseline, service_added)[0].change_type == "SERVICE"
    assert detector.compare(service_added, service_removed)[0].change_type == "SERVICE"
    assert detector.compare(baseline, owner_changed)[0].change_type == "OWNERSHIP"
    assert detector.compare(baseline, owner_conflict)[0].change_type == "OWNERSHIP"
    assert detector.compare(baseline, fingerprint_changed)[0].change_type == "FINGERPRINT"


def test_change_event_repository_is_idempotent_and_advances_temporal_bounds(
    session: Session,
) -> None:
    asset = _asset(session, "idempotent")
    detected = ChangeDetector().compare(_snapshot(), _snapshot(services=("tcp:443",)))[0]
    repository = ChangeEventRepository(session)

    first = repository.persist(asset.organization_id, asset.id, detected, NOW)
    session.flush()
    repeated = repository.persist(
        asset.organization_id,
        asset.id,
        detected,
        NOW + timedelta(hours=1),
    )
    historical = repository.persist(
        asset.organization_id,
        asset.id,
        detected,
        NOW - timedelta(hours=1),
    )
    session.commit()

    assert first.id == repeated.id == historical.id
    assert first.first_seen == NOW - timedelta(hours=1)
    assert first.last_seen == NOW + timedelta(hours=1)
    assert session.scalar(select(func.count(ChangeEvent.id))) == 1


def test_change_event_repository_denies_foreign_organization_asset(session: Session) -> None:
    asset = _asset(session, "origin")
    foreign = _asset(session, "foreign")
    detected = ChangeDetector().compare(_snapshot(), _snapshot(services=("tcp:443",)))[0]

    with pytest.raises(ValueError, match="not found in organization"):
        ChangeEventRepository(session).persist(foreign.organization_id, asset.id, detected, NOW)
