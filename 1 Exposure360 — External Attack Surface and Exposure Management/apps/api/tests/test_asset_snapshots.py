from datetime import UTC, datetime

from exposure360_api.asset_snapshots import (
    SNAPSHOT_SCHEMA_VERSION,
    AssetSnapshotBuilder,
    AssetSnapshotInput,
)


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
