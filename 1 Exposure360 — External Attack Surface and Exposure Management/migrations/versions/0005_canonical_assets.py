"""Create Phase 4 canonical asset inventory tables.

Revision ID: 0005_canonical_assets
Revises: 0004_discovery_staging
Create Date: 2026-08-20 05:35:00.000000
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0005_canonical_assets"
down_revision = "0004_discovery_staging"
branch_labels = None
depends_on = None


def _timestamp(name: str) -> sa.Column[object]:
    return sa.Column(
        name,
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.text("now()"),
    )


def _asset_reference(local_columns: list[str], name: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        local_columns,
        ["assets.id", "assets.organization_id"],
        name=name,
    )


def upgrade() -> None:
    uuid_type = postgresql.UUID(as_uuid=True)
    op.create_table(
        "assets",
        sa.Column("id", uuid_type, primary_key=True, nullable=False),
        sa.Column("organization_id", uuid_type, sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("asset_type", sa.String(length=16), nullable=False),
        sa.Column("canonical_key", sa.String(length=2048), nullable=False),
        sa.Column("display_name", sa.String(length=2048), nullable=False),
        sa.Column("lifecycle_state", sa.String(length=16), nullable=False, server_default="ACTIVE"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_from_discovery_job_id", uuid_type, nullable=True),
        _timestamp("created_at"),
        _timestamp("updated_at"),
        sa.UniqueConstraint("id", "organization_id", name="uq_asset_id_org"),
        sa.UniqueConstraint("organization_id", "canonical_key", name="uq_asset_org_canonical_key"),
        sa.ForeignKeyConstraint(
            ["created_from_discovery_job_id", "organization_id"],
            ["discovery_jobs.id", "discovery_jobs.organization_id"],
            name="fk_asset_discovery_job_org",
        ),
        sa.CheckConstraint(
            "asset_type IN ('DOMAIN', 'IP', 'ASN', 'ENDPOINT', 'SERVICE')",
            name="ck_asset_type",
        ),
        sa.CheckConstraint(
            "lifecycle_state IN ('ACTIVE', 'STALE', 'RETIRED')",
            name="ck_asset_lifecycle_state",
        ),
    )
    op.create_index("ix_assets_organization_id", "assets", ["organization_id"])
    op.create_index(
        "ix_assets_created_from_discovery_job_id",
        "assets",
        ["created_from_discovery_job_id"],
    )
    op.create_index(
        "ix_assets_org_type_last_seen",
        "assets",
        ["organization_id", "asset_type", "last_seen"],
    )

    op.create_table(
        "asset_identifiers",
        sa.Column("id", uuid_type, primary_key=True, nullable=False),
        sa.Column("organization_id", uuid_type, nullable=False),
        sa.Column("asset_id", uuid_type, nullable=False),
        sa.Column("identifier_type", sa.String(length=32), nullable=False),
        sa.Column("raw_value", sa.Text(), nullable=False),
        sa.Column("canonical_value", sa.String(length=2048), nullable=False),
        sa.Column("is_primary", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("source", sa.String(length=128), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        _timestamp("created_at"),
        _asset_reference(["asset_id", "organization_id"], "fk_asset_identifier_asset_org"),
        sa.UniqueConstraint(
            "organization_id",
            "identifier_type",
            "canonical_value",
            "asset_id",
            name="uq_asset_identifier_org_type_value_asset",
        ),
    )
    op.create_index(
        "ix_asset_identifiers_organization_id",
        "asset_identifiers",
        ["organization_id"],
    )
    op.create_index("ix_asset_identifiers_asset_id", "asset_identifiers", ["asset_id"])
    op.create_index(
        "ix_asset_identifiers_org_value",
        "asset_identifiers",
        ["organization_id", "canonical_value"],
    )

    _create_subtype_tables(uuid_type)


def _create_subtype_tables(uuid_type: postgresql.UUID) -> None:
    op.create_table(
        "domain_assets",
        sa.Column("asset_id", uuid_type, primary_key=True, nullable=False),
        sa.Column("organization_id", uuid_type, nullable=False),
        sa.Column("fqdn_ascii", sa.String(length=253), nullable=False),
        sa.Column("fqdn_unicode", sa.String(length=253), nullable=True),
        sa.Column("registrable_domain", sa.String(length=253), nullable=True),
        _asset_reference(["asset_id", "organization_id"], "fk_domain_asset_asset_org"),
        sa.UniqueConstraint("organization_id", "fqdn_ascii", name="uq_domain_asset_org_fqdn"),
    )
    op.create_table(
        "ip_assets",
        sa.Column("asset_id", uuid_type, primary_key=True, nullable=False),
        sa.Column("organization_id", uuid_type, nullable=False),
        sa.Column("address", sa.String(length=45), nullable=False),
        sa.Column("ip_version", sa.Integer(), nullable=False),
        sa.Column("is_global", sa.Boolean(), nullable=False),
        sa.Column("address_class", sa.String(length=32), nullable=False),
        _asset_reference(["asset_id", "organization_id"], "fk_ip_asset_asset_org"),
        sa.UniqueConstraint("organization_id", "address", name="uq_ip_asset_org_address"),
        sa.CheckConstraint("ip_version IN (4, 6)", name="ck_ip_asset_version"),
    )
    op.create_table(
        "asn_assets",
        sa.Column("asset_id", uuid_type, primary_key=True, nullable=False),
        sa.Column("organization_id", uuid_type, nullable=False),
        sa.Column("asn_number", sa.Integer(), nullable=False),
        sa.Column("canonical_asn", sa.String(length=16), nullable=False),
        sa.Column("name_hint", sa.String(length=255), nullable=True),
        _asset_reference(["asset_id", "organization_id"], "fk_asn_asset_asset_org"),
        sa.UniqueConstraint("organization_id", "asn_number", name="uq_asn_asset_org_number"),
        sa.CheckConstraint("asn_number BETWEEN 1 AND 4294967295", name="ck_asn_asset_number"),
    )
    op.create_table(
        "endpoint_assets",
        sa.Column("asset_id", uuid_type, primary_key=True, nullable=False),
        sa.Column("organization_id", uuid_type, nullable=False),
        sa.Column("ip_asset_id", uuid_type, nullable=False),
        sa.Column("transport_protocol", sa.String(length=8), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        _timestamp("created_at"),
        _asset_reference(["asset_id", "organization_id"], "fk_endpoint_asset_asset_org"),
        _asset_reference(["ip_asset_id", "organization_id"], "fk_endpoint_asset_ip_org"),
        sa.UniqueConstraint(
            "organization_id",
            "ip_asset_id",
            "transport_protocol",
            "port",
            name="uq_endpoint_asset_org_socket",
        ),
        sa.CheckConstraint("transport_protocol IN ('TCP')", name="ck_endpoint_asset_transport"),
        sa.CheckConstraint("port BETWEEN 1 AND 65535", name="ck_endpoint_asset_port"),
    )
    op.create_table(
        "service_assets",
        sa.Column("asset_id", uuid_type, primary_key=True, nullable=False),
        sa.Column("organization_id", uuid_type, nullable=False),
        sa.Column("endpoint_asset_id", uuid_type, nullable=False),
        sa.Column("service_kind", sa.String(length=16), nullable=False),
        sa.Column("application_protocol", sa.String(length=16), nullable=False),
        sa.Column("authority_domain_asset_id", uuid_type, nullable=True),
        sa.Column("service_key", sa.String(length=2048), nullable=False),
        _asset_reference(["asset_id", "organization_id"], "fk_service_asset_asset_org"),
        _asset_reference(
            ["endpoint_asset_id", "organization_id"],
            "fk_service_asset_endpoint_org",
        ),
        _asset_reference(
            ["authority_domain_asset_id", "organization_id"],
            "fk_service_asset_authority_org",
        ),
        sa.UniqueConstraint("organization_id", "service_key", name="uq_service_asset_org_key"),
        sa.CheckConstraint(
            "service_kind IN ('HTTP', 'HTTPS', 'TLS', 'UNKNOWN_TCP')",
            name="ck_service_asset_kind",
        ),
        sa.CheckConstraint(
            "application_protocol IN ('HTTP', 'HTTPS', 'TLS', 'UNKNOWN_TCP')",
            name="ck_service_asset_protocol",
        ),
    )


def downgrade() -> None:
    op.drop_table("service_assets")
    op.drop_table("endpoint_assets")
    op.drop_table("asn_assets")
    op.drop_table("ip_assets")
    op.drop_table("domain_assets")
    op.drop_table("asset_identifiers")
    op.drop_table("assets")
