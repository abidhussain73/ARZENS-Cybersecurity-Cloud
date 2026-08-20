"""Create versioned technology fingerprint persistence.

Revision ID: 0009_technology_fingerprints
Revises: 0008_ownership
Create Date: 2026-08-20 06:05:00.000000
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0009_technology_fingerprints"
down_revision = "0008_ownership"
branch_labels = None
depends_on = None


def _timestamp(name: str) -> sa.Column[object]:
    return sa.Column(
        name,
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.text("now()"),
    )


def _organization_reference(
    local_id: str,
    remote_table: str,
    constraint_name: str,
) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        [local_id, "organization_id"],
        [f"{remote_table}.id", f"{remote_table}.organization_id"],
        name=constraint_name,
    )


def upgrade() -> None:
    uuid_type = postgresql.UUID(as_uuid=True)
    op.create_table(
        "technology_fingerprints",
        sa.Column("id", uuid_type, primary_key=True, nullable=False),
        sa.Column("organization_id", uuid_type, nullable=False),
        sa.Column("asset_id", uuid_type, nullable=False),
        sa.Column("service_asset_id", uuid_type, nullable=True),
        sa.Column("technology_vendor", sa.String(length=255), nullable=True),
        sa.Column("technology_product", sa.String(length=255), nullable=False),
        sa.Column("technology_category", sa.String(length=128), nullable=False),
        sa.Column("version_value", sa.String(length=255), nullable=True),
        sa.Column("version_confidence", sa.Float(), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("confidence_model_version", sa.String(length=64), nullable=False),
        sa.Column("rule_id", sa.String(length=255), nullable=False),
        sa.Column("rule_version", sa.Integer(), nullable=False),
        sa.Column("rule_hash", sa.String(length=64), nullable=False),
        sa.Column("ruleset_hash", sa.String(length=64), nullable=False),
        sa.Column("fingerprint_key", sa.String(length=64), nullable=False),
        sa.Column(
            "evidence_fields_json",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'[]'::json"),
        ),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        _timestamp("created_at"),
        _timestamp("updated_at"),
        sa.UniqueConstraint("id", "organization_id", name="uq_technology_fingerprint_id_org"),
        sa.UniqueConstraint(
            "organization_id",
            "fingerprint_key",
            name="uq_technology_fingerprint_org_key",
        ),
        _organization_reference("asset_id", "assets", "fk_technology_fingerprint_asset_org"),
        _organization_reference(
            "service_asset_id",
            "assets",
            "fk_technology_fingerprint_service_org",
        ),
        sa.CheckConstraint(
            "confidence >= 0 AND confidence <= 1",
            name="ck_technology_fingerprint_confidence",
        ),
        sa.CheckConstraint(
            "version_confidence IS NULL OR "
            "(version_confidence >= 0 AND version_confidence <= 1)",
            name="ck_technology_fingerprint_version_confidence",
        ),
    )
    op.create_index(
        "ix_technology_fingerprints_organization_id",
        "technology_fingerprints",
        ["organization_id"],
    )
    op.create_index(
        "ix_technology_fingerprints_asset_id",
        "technology_fingerprints",
        ["asset_id"],
    )
    op.create_index(
        "ix_technology_fingerprints_asset_seen",
        "technology_fingerprints",
        ["asset_id", "last_seen"],
    )
    op.create_table(
        "fingerprint_evidence_links",
        sa.Column("id", uuid_type, primary_key=True, nullable=False),
        sa.Column("organization_id", uuid_type, nullable=False),
        sa.Column("fingerprint_id", uuid_type, nullable=False),
        sa.Column("observation_id", uuid_type, nullable=False),
        sa.Column("evidence_id", uuid_type, nullable=True),
        sa.Column("link_key", sa.String(length=64), nullable=False),
        _timestamp("created_at"),
        sa.UniqueConstraint(
            "organization_id",
            "link_key",
            name="uq_fingerprint_evidence_link_org_key",
        ),
        _organization_reference(
            "fingerprint_id",
            "technology_fingerprints",
            "fk_fingerprint_evidence_link_fingerprint_org",
        ),
        _organization_reference(
            "observation_id",
            "canonical_observations",
            "fk_fingerprint_evidence_link_observation_org",
        ),
        _organization_reference(
            "evidence_id",
            "evidence",
            "fk_fingerprint_evidence_link_evidence_org",
        ),
    )
    op.create_index(
        "ix_fingerprint_evidence_links_organization_id",
        "fingerprint_evidence_links",
        ["organization_id"],
    )
    op.create_index(
        "ix_fingerprint_evidence_links_fingerprint_id",
        "fingerprint_evidence_links",
        ["fingerprint_id"],
    )
    op.create_index(
        "ix_fingerprint_evidence_links_observation_id",
        "fingerprint_evidence_links",
        ["observation_id"],
    )


def downgrade() -> None:
    op.drop_table("fingerprint_evidence_links")
    op.drop_table("technology_fingerprints")
