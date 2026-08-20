import uuid

from sqlalchemy.orm import Session

from .models import Asset, DomainAsset, EndpointAsset, ServiceAsset


class CanonicalAssetValidationError(ValueError):
    """Raised when canonical subtype links would violate asset semantics."""


class CanonicalAssetRepository:
    """Validates direct Phase 4 structural links before persistence."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def add_service(self, service: ServiceAsset) -> None:
        self._require_asset_type(service.asset_id, service.organization_id, "SERVICE")
        endpoint = self._session.get(EndpointAsset, service.endpoint_asset_id)
        if endpoint is None or endpoint.organization_id != service.organization_id:
            raise CanonicalAssetValidationError(
                "service endpoint parent must be an endpoint asset in the same organization"
            )
        if service.authority_domain_asset_id is not None:
            authority = self._session.get(DomainAsset, service.authority_domain_asset_id)
            if authority is None or authority.organization_id != service.organization_id:
                raise CanonicalAssetValidationError(
                    "service authority must be a domain asset in the same organization"
                )
        self._session.add(service)

    def _require_asset_type(
        self, asset_id: uuid.UUID, organization_id: uuid.UUID, asset_type: str
    ) -> None:
        asset = self._session.get(Asset, asset_id)
        if (
            asset is None
            or asset.organization_id != organization_id
            or asset.asset_type != asset_type
        ):
            raise CanonicalAssetValidationError(
                f"canonical asset must be a {asset_type} in the same organization"
            )
