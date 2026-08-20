"""Pure typed comparisons for compatible canonical asset snapshots."""

from dataclasses import dataclass
from typing import Literal, cast

ChangeType = Literal["NEW", "REMOVED", "SERVICE", "CERTIFICATE", "OWNERSHIP", "FINGERPRINT"]


@dataclass(frozen=True)
class DetectedChange:
    change_type: ChangeType
    component_key: str
    old: object | None
    new: object | None


class ChangeDetector:
    def compare(
        self, previous: dict[str, object] | None, current: dict[str, object] | None
    ) -> tuple[DetectedChange, ...]:
        if previous is None and current is None:
            return ()
        if previous is None:
            assert current is not None
            asset = cast(dict[str, object], current["asset"])
            return (DetectedChange("NEW", str(asset["canonical_key"]), None, current),)
        if current is None:
            asset = cast(dict[str, object], previous["asset"])
            return (DetectedChange("REMOVED", str(asset["canonical_key"]), previous, None),)
        if previous.get("schema_version") != current.get("schema_version"):
            raise ValueError("incompatible snapshot schema versions")
        changes: list[DetectedChange] = []
        if previous.get("ownership") != current.get("ownership"):
            changes.append(
                DetectedChange(
                    "OWNERSHIP", "ownership", previous.get("ownership"), current.get("ownership")
                )
            )
        if previous.get("technologies") != current.get("technologies"):
            changes.append(
                DetectedChange(
                    "FINGERPRINT",
                    "technologies",
                    previous.get("technologies"),
                    current.get("technologies"),
                )
            )
        if previous.get("services") != current.get("services"):
            changes.append(
                DetectedChange(
                    "SERVICE", "services", previous.get("services"), current.get("services")
                )
            )
        return tuple(changes)
