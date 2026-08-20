import pytest

from exposure360_api.change_detector import ChangeDetector


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
