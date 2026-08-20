from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from exposure360_api.asset_snapshots import (
    SNAPSHOT_SCHEMA_VERSION,
    AssetSnapshotBuilder,
    AssetSnapshotInput,
    AssetSnapshotRepository,
)
from exposure360_api.db import Base
from exposure360_api.models import Asset, Organization

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


def _input(
    last_seen: datetime,
    services: tuple[dict[str, object], ...] = (),
) -> AssetSnapshotInput:
    return AssetSnapshotInput(
        asset_type="DOMAIN",
        canonical_key="domain:fixture.example.test",
        lifecycle_state="ACTIVE",
        display_last_seen=last_seen,
        ownership={"primary_owner": "team:alpha", "state": "RESOLVED"},
        resolved_ips=("192.0.2.21", "192.0.2.20"),
        services=services,
        technologies=({"product": "FixtureWeb", "version": "1.2.3"},),
    )


def test_snapshot_serialization_is_stable_and_excludes_last_seen_from_structural_hash() -> None:
    builder = AssetSnapshotBuilder()
    first = builder.build(_input(datetime(2026, 1, 20, tzinfo=UTC)))
    second = builder.build(_input(datetime(2026, 1, 21, tzinfo=UTC)))
    assert first.schema_version == SNAPSHOT_SCHEMA_VERSION
    assert first.snapshot_hash == second.snapshot_hash
    assert first.snapshot_json["display"] != second.snapshot_json["display"]
    assert first.comparison_projection["relationships"] == {
        "resolved_ips": ["192.0.2.20", "192.0.2.21"]
    }


def test_services_are_ordered_and_structural_changes_change_hash() -> None:
    builder = AssetSnapshotBuilder()
    services = (
        {
            "protocol": "HTTPS",
            "endpoint": "tcp:192.0.2.20:443",
            "certificate_fingerprint": "b",
        },
        {
            "protocol": "HTTP",
            "endpoint": "tcp:192.0.2.20:80",
            "certificate_fingerprint": "a",
        },
    )
    initial = builder.build(_input(datetime(2026, 1, 20, tzinfo=UTC), tuple(reversed(services))))
    ordered = builder.build(_input(datetime(2026, 1, 20, tzinfo=UTC), services))
    changed = builder.build(
        _input(
            datetime(2026, 1, 20, tzinfo=UTC),
            services + ({"protocol": "TLS", "endpoint": "tcp:192.0.2.20:8443"},),
        )
    )
    assert initial.snapshot_hash == ordered.snapshot_hash
    assert changed.snapshot_hash != ordered.snapshot_hash


def test_same_snapshot_at_same_time_is_idempotently_persisted(session: Session) -> None:
    asset = _asset(session, "idempotent")
    snapshot = AssetSnapshotBuilder().build(_input(NOW))
    repository = AssetSnapshotRepository(session)

    first = repository.persist(asset.organization_id, asset.id, NOW, snapshot)
    session.flush()
    repeated = repository.persist(asset.organization_id, asset.id, NOW, snapshot)

    assert first.id == repeated.id


def test_snapshot_repository_denies_cross_organization_asset_access(session: Session) -> None:
    asset = _asset(session, "origin")
    foreign = _asset(session, "foreign")
    snapshot = AssetSnapshotBuilder().build(_input(NOW))

    with pytest.raises(ValueError, match="not found in organization"):
        AssetSnapshotRepository(session).persist(foreign.organization_id, asset.id, NOW, snapshot)


@pytest.mark.parametrize(
    "changed_input",
    [
        _input(NOW, ({"protocol": "HTTPS", "endpoint": "tcp:192.0.2.20:443"},)),
        AssetSnapshotInput(
            asset_type="DOMAIN",
            canonical_key="domain:fixture.example.test",
            lifecycle_state="ACTIVE",
            display_last_seen=NOW,
            ownership={"primary_owner": "team:alpha", "state": "RESOLVED"},
            resolved_ips=("192.0.2.21", "192.0.2.20"),
            services=(
                {
                    "protocol": "HTTPS",
                    "endpoint": "tcp:192.0.2.20:443",
                    "certificate_fingerprint": "rotated-certificate",
                },
            ),
            technologies=({"product": "FixtureWeb", "version": "1.2.3"},),
        ),
        AssetSnapshotInput(
            asset_type="DOMAIN",
            canonical_key="domain:fixture.example.test",
            lifecycle_state="ACTIVE",
            display_last_seen=NOW,
            ownership={"primary_owner": "team:bravo", "state": "RESOLVED"},
            resolved_ips=("192.0.2.21", "192.0.2.20"),
            services=(),
            technologies=({"product": "FixtureWeb", "version": "1.2.3"},),
        ),
        AssetSnapshotInput(
            asset_type="DOMAIN",
            canonical_key="domain:fixture.example.test",
            lifecycle_state="ACTIVE",
            display_last_seen=NOW,
            ownership={"primary_owner": "team:alpha", "state": "RESOLVED"},
            resolved_ips=("192.0.2.21", "192.0.2.20"),
            services=(),
            technologies=({"product": "FixtureWeb", "version": "1.3.0"},),
        ),
    ],
    ids=("service-addition", "certificate-change", "owner-change", "fingerprint-change"),
)
def test_structural_snapshot_categories_change_the_hash(changed_input: AssetSnapshotInput) -> None:
    builder = AssetSnapshotBuilder()

    assert builder.build(_input(NOW)).snapshot_hash != builder.build(changed_input).snapshot_hash
