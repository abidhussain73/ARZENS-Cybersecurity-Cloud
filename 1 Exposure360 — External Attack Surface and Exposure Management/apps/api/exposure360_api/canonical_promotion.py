import ipaddress
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .canonical_assets import CanonicalAssetRepository
from .discovery_contracts import CandidateType
from .models import (
    Asset,
    AssetIdentifier,
    CandidateAsset,
    DomainAsset,
    EndpointAsset,
    IpAsset,
    ServiceAsset,
)
from .scope_governance import ScopeTargetNormalizer


class CanonicalPromotionError(ValueError):
    """Raised when staging data cannot satisfy canonical promotion rules."""


@dataclass(frozen=True)
class CanonicalKey:
    asset_type: str
    canonical_value: str
    canonical_key: str


class CanonicalAssetKeyFactory:
    """Creates documented, deterministic Phase 4 keys without source-specific identity."""

    @staticmethod
    def domain(raw_value: str) -> CanonicalKey:
        normalized = ScopeTargetNormalizer.normalize_domain(raw_value).canonical_value
        return CanonicalKey("DOMAIN", normalized, f"domain:{normalized}")

    @staticmethod
    def ip(raw_value: str) -> CanonicalKey:
        value = raw_value.split("/", 1)[0]
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise CanonicalPromotionError("IP asset value is invalid") from exc
        canonical = address.compressed
        return CanonicalKey("IP", canonical, f"ip:{canonical}")

    @staticmethod
    def asn(raw_value: str) -> CanonicalKey:
        normalized = ScopeTargetNormalizer.normalize_asn(raw_value).canonical_value
        return CanonicalKey("ASN", normalized, f"asn:{normalized}")

    @classmethod
    def endpoint(cls, raw_ip: str, transport_protocol: str, port: int) -> CanonicalKey:
        if transport_protocol != "TCP":
            raise CanonicalPromotionError("only TCP endpoint identity is supported in Phase 4")
        if not 1 <= port <= 65535:
            raise CanonicalPromotionError("endpoint port must be between 1 and 65535")
        canonical_ip = cls.ip(raw_ip).canonical_value
        serialized_ip = f"[{canonical_ip}]" if ":" in canonical_ip else canonical_ip
        value = f"{transport_protocol.lower()}:{serialized_ip}:{port}"
        return CanonicalKey("ENDPOINT", value, f"endpoint:{value}")

    @classmethod
    def service(
        cls,
        endpoint_key: CanonicalKey,
        application_protocol: str,
        authority_domain: str | None,
    ) -> CanonicalKey:
        if endpoint_key.asset_type != "ENDPOINT":
            raise CanonicalPromotionError("service identity requires an endpoint canonical key")
        protocol = application_protocol.upper()
        if protocol not in {"HTTP", "HTTPS", "TLS", "UNKNOWN_TCP"}:
            raise CanonicalPromotionError("unsupported service application protocol")
        authority = (
            "-" if authority_domain is None else cls.domain(authority_domain).canonical_value
        )
        endpoint_value = endpoint_key.canonical_key.removeprefix("endpoint:")
        value = f"{endpoint_value}:{protocol.lower()}:{authority}"
        return CanonicalKey("SERVICE", value, f"service:{value}")


class CanonicalAssetPromoter:
    """Promotes Phase 3 staging candidates through the canonical asset boundary."""

    def promote_candidate(
        self,
        session: Session,
        candidate: CandidateAsset,
        *,
        source: str,
    ) -> Asset | None:
        if candidate.candidate_type == CandidateType.DOMAIN.value:
            return self.promote_domain(
                session,
                organization_id=candidate.organization_id,
                raw_value=candidate.raw_value,
                observed_at=candidate.last_discovered_at,
                source=source,
            )
        if candidate.candidate_type == CandidateType.IP.value:
            return self.promote_ip(
                session,
                organization_id=candidate.organization_id,
                raw_value=candidate.canonical_value,
                observed_at=candidate.last_discovered_at,
                source=source,
            )
        return None

    def promote_domain(
        self,
        session: Session,
        *,
        organization_id: uuid.UUID,
        raw_value: str,
        observed_at: datetime,
        source: str,
    ) -> Asset:
        key = CanonicalAssetKeyFactory.domain(raw_value)
        asset, created = self._get_or_create_asset(session, organization_id, key, observed_at)
        if created:
            unicode_value = self._unicode_domain(key.canonical_value)
            session.add(
                DomainAsset(
                    asset_id=asset.id,
                    organization_id=organization_id,
                    fqdn_ascii=key.canonical_value,
                    fqdn_unicode=unicode_value,
                    registrable_domain=None,
                )
            )
        self._upsert_identifier(
            session,
            asset,
            "FQDN",
            raw_value,
            key.canonical_value,
            source,
            observed_at,
        )
        return asset

    def promote_ip(
        self,
        session: Session,
        *,
        organization_id: uuid.UUID,
        raw_value: str,
        observed_at: datetime,
        source: str,
    ) -> Asset:
        key = CanonicalAssetKeyFactory.ip(raw_value)
        asset, created = self._get_or_create_asset(session, organization_id, key, observed_at)
        if created:
            address = ipaddress.ip_address(key.canonical_value)
            session.add(
                IpAsset(
                    asset_id=asset.id,
                    organization_id=organization_id,
                    address=key.canonical_value,
                    ip_version=address.version,
                    is_global=address.is_global,
                    address_class=self._address_class(address),
                )
            )
        self._upsert_identifier(
            session, asset, "IP_ADDRESS", raw_value, key.canonical_value, source, observed_at
        )
        return asset

    def promote_endpoint(
        self,
        session: Session,
        *,
        organization_id: uuid.UUID,
        raw_ip: str,
        port: int,
        observed_at: datetime,
        source: str,
    ) -> Asset:
        ip_asset = self.promote_ip(
            session,
            organization_id=organization_id,
            raw_value=raw_ip,
            observed_at=observed_at,
            source=source,
        )
        key = CanonicalAssetKeyFactory.endpoint(raw_ip, "TCP", port)
        asset, created = self._get_or_create_asset(session, organization_id, key, observed_at)
        if created:
            session.add(
                EndpointAsset(
                    asset_id=asset.id,
                    organization_id=organization_id,
                    ip_asset_id=ip_asset.id,
                    transport_protocol="TCP",
                    port=port,
                )
            )
        self._upsert_identifier(
            session,
            asset,
            "SOCKET",
            key.canonical_value,
            key.canonical_value,
            source,
            observed_at,
        )
        return asset

    def promote_service(
        self,
        session: Session,
        *,
        endpoint: Asset,
        application_protocol: str,
        authority_domain: Asset | None,
        observed_at: datetime,
    ) -> Asset:
        endpoint_key = CanonicalKey(
            "ENDPOINT",
            endpoint.canonical_key.removeprefix("endpoint:"),
            endpoint.canonical_key,
        )
        authority = authority_domain.display_name if authority_domain is not None else None
        key = CanonicalAssetKeyFactory.service(endpoint_key, application_protocol, authority)
        asset, created = self._get_or_create_asset(
            session, endpoint.organization_id, key, observed_at
        )
        if created:
            CanonicalAssetRepository(session).add_service(
                ServiceAsset(
                    asset_id=asset.id,
                    organization_id=endpoint.organization_id,
                    endpoint_asset_id=endpoint.id,
                    service_kind=application_protocol.upper(),
                    application_protocol=application_protocol.upper(),
                    authority_domain_asset_id=(
                        None if authority_domain is None else authority_domain.id
                    ),
                    service_key=key.canonical_value,
                )
            )
        return asset

    def _get_or_create_asset(
        self,
        session: Session,
        organization_id: uuid.UUID,
        key: CanonicalKey,
        observed_at: datetime,
    ) -> tuple[Asset, bool]:
        asset = session.scalar(
            select(Asset).where(
                Asset.organization_id == organization_id,
                Asset.canonical_key == key.canonical_key,
            )
        )
        if asset is not None:
            asset.first_seen = min(self._as_utc(asset.first_seen), self._as_utc(observed_at))
            asset.last_seen = max(self._as_utc(asset.last_seen), self._as_utc(observed_at))
            return asset, False
        asset = Asset(
            organization_id=organization_id,
            asset_type=key.asset_type,
            canonical_key=key.canonical_key,
            display_name=key.canonical_value,
            lifecycle_state="ACTIVE",
            first_seen=observed_at,
            last_seen=observed_at,
        )
        try:
            with session.begin_nested():
                session.add(asset)
                session.flush()
        except IntegrityError:
            asset = session.scalar(
                select(Asset).where(
                    Asset.organization_id == organization_id,
                    Asset.canonical_key == key.canonical_key,
                )
            )
            if asset is None:
                raise
            return asset, False
        return asset, True

    @staticmethod
    def _upsert_identifier(
        session: Session,
        asset: Asset,
        identifier_type: str,
        raw_value: str,
        canonical_value: str,
        source: str,
        observed_at: datetime,
    ) -> None:
        identifier = session.scalar(
            select(AssetIdentifier).where(
                AssetIdentifier.organization_id == asset.organization_id,
                AssetIdentifier.asset_id == asset.id,
                AssetIdentifier.identifier_type == identifier_type,
                AssetIdentifier.canonical_value == canonical_value,
            )
        )
        if identifier is None:
            session.add(
                AssetIdentifier(
                    organization_id=asset.organization_id,
                    asset_id=asset.id,
                    identifier_type=identifier_type,
                    raw_value=raw_value,
                    canonical_value=canonical_value,
                    is_primary=True,
                    source=source,
                    first_seen=observed_at,
                    last_seen=observed_at,
                )
            )
            return
        identifier.first_seen = min(
            CanonicalAssetPromoter._as_utc(identifier.first_seen), observed_at
        )
        identifier.last_seen = max(
            CanonicalAssetPromoter._as_utc(identifier.last_seen), observed_at
        )

    @staticmethod
    def _address_class(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
        if address.is_loopback:
            return "LOOPBACK"
        if address.is_private:
            return "PRIVATE"
        if address.is_reserved:
            return "RESERVED"
        if address.is_multicast:
            return "MULTICAST"
        if address.is_unspecified:
            return "UNSPECIFIED"
        if address.is_global:
            return "GLOBAL"
        return "DOCUMENTATION"

    @staticmethod
    def _unicode_domain(value: str) -> str | None:
        decoded = value.encode("ascii").decode("idna")
        return None if decoded == value else decoded

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)
