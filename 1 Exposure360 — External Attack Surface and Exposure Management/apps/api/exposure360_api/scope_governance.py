import hashlib
import ipaddress
import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Literal

TargetType = Literal["DOMAIN", "CIDR", "IP", "ASN"]
MatchMode = Literal["EXACT", "DOMAIN_AND_SUBDOMAINS"]
Severity = Literal["ERROR", "WARNING", "INFO"]

_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_ASN = re.compile(r"^(?:AS)?([0-9]+)$", re.IGNORECASE)
_MAX_ASN = 4_294_967_295


class ScopeValidationError(ValueError):
    """Raised when a security-relevant scope value is not unambiguous."""


@dataclass(frozen=True)
class NormalizedTarget:
    target_type: TargetType
    raw_value: str
    canonical_value: str
    warning: str | None = None


@dataclass(frozen=True)
class TargetRule:
    target_type: TargetType
    canonical_value: str
    match_mode: MatchMode = "EXACT"


@dataclass(frozen=True)
class ConflictFinding:
    severity: Severity
    code: str
    message: str


@dataclass(frozen=True)
class ConflictReport:
    errors: tuple[ConflictFinding, ...]
    warnings: tuple[ConflictFinding, ...]

    @property
    def is_approvable(self) -> bool:
        return not self.errors


class ScopeTargetNormalizer:
    @staticmethod
    def normalize_domain(raw_value: str) -> NormalizedTarget:
        if not isinstance(raw_value, str):
            raise ScopeValidationError("Domain value must be text")
        if any(unicodedata.category(character).startswith("C") for character in raw_value):
            raise ScopeValidationError("Domain contains control or invisible characters")
        value = raw_value.strip()
        if not value or any(character.isspace() for character in value):
            raise ScopeValidationError("Domain must not be empty or contain whitespace")
        if any(character in value for character in (":", "/", "@", "?", "#")):
            raise ScopeValidationError("Domain seed must not contain URL syntax")
        if value.endswith("."):
            value = value[:-1]
        if not value:
            raise ScopeValidationError("Domain must not be empty")
        try:
            canonical = value.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ScopeValidationError("Domain is not valid IDNA") from exc
        if len(canonical) > 253:
            raise ScopeValidationError("Domain exceeds 253 characters")
        labels = canonical.split(".")
        if any(not label or not _DOMAIN_LABEL.fullmatch(label) for label in labels):
            raise ScopeValidationError("Domain has an invalid DNS label")
        warning = None if canonical == raw_value else f"Normalized to {canonical}"
        return NormalizedTarget("DOMAIN", raw_value, canonical, warning)

    @staticmethod
    def normalize_network(raw_value: str) -> NormalizedTarget:
        if not isinstance(raw_value, str):
            raise ScopeValidationError("CIDR value must be text")
        value = raw_value.strip()
        if "/" not in value:
            raise ScopeValidationError("CIDR seed requires a prefix length")
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ScopeValidationError("CIDR is invalid") from exc
        if network.prefixlen == 0:
            raise ScopeValidationError("Global catch-all CIDR seeds are not allowed")
        canonical = network.with_prefixlen
        warning = None if canonical == value else f"Normalized to {canonical}"
        return NormalizedTarget("CIDR", raw_value, canonical, warning)

    @staticmethod
    def normalize_ip(raw_value: str) -> NormalizedTarget:
        if not isinstance(raw_value, str):
            raise ScopeValidationError("IP value must be text")
        value = raw_value.strip()
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ScopeValidationError("IP is invalid") from exc
        canonical = f"{address.compressed}/{address.max_prefixlen}"
        warning = None if canonical == value else f"Normalized to {canonical}"
        return NormalizedTarget("IP", raw_value, canonical, warning)

    @staticmethod
    def normalize_asn(raw_value: str) -> NormalizedTarget:
        if not isinstance(raw_value, str):
            raise ScopeValidationError("ASN value must be text")
        value = raw_value.strip()
        match = _ASN.fullmatch(value)
        if match is None:
            raise ScopeValidationError("ASN must be numeric or AS-prefixed")
        number = int(match.group(1))
        if not 1 <= number <= _MAX_ASN:
            raise ScopeValidationError("ASN is outside the supported 32-bit range")
        canonical = f"AS{number}"
        warning = None if canonical == value else f"Normalized to {canonical}"
        return NormalizedTarget("ASN", raw_value, canonical, warning)

    @classmethod
    def normalize_target(cls, target_type: TargetType, raw_value: str) -> NormalizedTarget:
        normalizers = {
            "DOMAIN": cls.normalize_domain,
            "CIDR": cls.normalize_network,
            "IP": cls.normalize_ip,
            "ASN": cls.normalize_asn,
        }
        try:
            return normalizers[target_type](raw_value)
        except KeyError as exc:
            raise ScopeValidationError("Unsupported target type") from exc


def domain_matches(candidate: str, seed: str, match_mode: MatchMode) -> bool:
    if candidate == seed:
        return True
    return match_mode == "DOMAIN_AND_SUBDOMAINS" and candidate.endswith(f".{seed}")


def target_matches(rule: TargetRule, candidate_type: TargetType, candidate: str) -> bool:
    normalized = ScopeTargetNormalizer.normalize_target(candidate_type, candidate)
    if rule.target_type == "DOMAIN" and normalized.target_type == "DOMAIN":
        return domain_matches(normalized.canonical_value, rule.canonical_value, rule.match_mode)
    if rule.target_type in {"CIDR", "IP"} and normalized.target_type in {"CIDR", "IP"}:
        network = ipaddress.ip_network(rule.canonical_value, strict=True)
        candidate_network = ipaddress.ip_network(normalized.canonical_value, strict=True)
        return network.version == candidate_network.version and (
            candidate_network.network_address in network
            and candidate_network.broadcast_address in network
        )
    return (
        rule.target_type == normalized.target_type
        and rule.canonical_value == normalized.canonical_value
    )


def calculate_content_hash(
    *,
    scope_version_id: str,
    seeds: list[TargetRule],
    exclusions: list[TargetRule],
    policy: dict[str, object],
) -> str:
    payload = {
        "scope_version_id": scope_version_id,
        "seeds": sorted(
            [rule.__dict__ for rule in seeds], key=lambda item: json.dumps(item, sort_keys=True)
        ),
        "exclusions": sorted(
            [rule.__dict__ for rule in exclusions],
            key=lambda item: json.dumps(item, sort_keys=True),
        ),
        "policy": policy,
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ScopeConflictAnalyzer:
    @staticmethod
    def analyze(seeds: list[TargetRule], exclusions: list[TargetRule]) -> ConflictReport:
        errors: list[ConflictFinding] = []
        warnings: list[ConflictFinding] = []
        for index, seed in enumerate(seeds):
            for other in seeds[index + 1 :]:
                finding = ScopeConflictAnalyzer._seed_relationship(seed, other)
                if finding is not None:
                    errors.append(finding)
            for exclusion in exclusions:
                if ScopeConflictAnalyzer._rules_overlap(seed, exclusion):
                    warnings.append(
                        ConflictFinding(
                            "WARNING",
                            "EXCLUSION_OVERLAPS_SEED",
                            f"Exclusion {exclusion.canonical_value} overrides inclusion "
                            f"{seed.canonical_value}",
                        )
                    )
        for exclusion in exclusions:
            if not any(ScopeConflictAnalyzer._rules_overlap(seed, exclusion) for seed in seeds):
                warnings.append(
                    ConflictFinding(
                        "WARNING",
                        "EXCLUSION_OUTSIDE_SCOPE",
                        f"Exclusion {exclusion.canonical_value} does not overlap an inclusion",
                    )
                )
        return ConflictReport(tuple(errors), tuple(warnings))

    @staticmethod
    def _seed_relationship(first: TargetRule, second: TargetRule) -> ConflictFinding | None:
        if first == second:
            return ConflictFinding("ERROR", "DUPLICATE", f"Duplicate seed {first.canonical_value}")
        if ScopeConflictAnalyzer._rules_overlap(first, second):
            return ConflictFinding(
                "ERROR",
                "REDUNDANT",
                f"Overlapping seeds {first.canonical_value} and "
                f"{second.canonical_value} are ambiguous",
            )
        return None

    @staticmethod
    def _rules_overlap(first: TargetRule, second: TargetRule) -> bool:
        if first.target_type != second.target_type:
            return False
        if first.target_type == "DOMAIN":
            return domain_matches(
                first.canonical_value, second.canonical_value, second.match_mode
            ) or domain_matches(
                second.canonical_value,
                first.canonical_value,
                first.match_mode,
            )
        if first.target_type in {"CIDR", "IP"}:
            first_network = ipaddress.ip_network(first.canonical_value, strict=True)
            second_network = ipaddress.ip_network(second.canonical_value, strict=True)
            return first_network.overlaps(second_network)
        return first.canonical_value == second.canonical_value
