"""Create Phase 4 ownership claims and evidence links.

Revision ID: 0008_ownership
Revises: 0007_observations_evidence
Create Date: 2026-08-20 05:50:00.000000
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0008_ownership"
down_revision = "0007_observations_evidence"
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
        "asset_ownerships",
        sa.Column("id", uuid_type, primary_key=True, nullable=False),
        sa.Column("organization_id", uuid_type, nullable=False),
        sa.Column("asset_id", uuid_type, nullable=False),
        sa.Column("owner_type", sa.String(length=32), nullable=False),
        sa.Column("owner_reference", sa.String(length=255), nullable=False),
        sa.Column("owner_display_name", sa.String(length=255), nullable=True),
        sa.Column("claim_type", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("source_type", sa.String(length=64), nullable=False),
        sa.Column("claim_key", sa.String(length=64), nullable=False),
        sa.Column("is_primary", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_to", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reason", sa.String(length=512), nullable=True),
        sa.Column(
            "created_by_user_id",
            uuid_type,
            sa.ForeignKey("users.id"),
            nullable=True,
        ),
        _timestamp("created_at"),
        _timestamp("updated_at"),
        sa.UniqueConstraint("id", "organization_id", name="uq_asset_ownership_id_org"),
        sa.UniqueConstraint(
            "organization_id",
            "asset_id",
            "claim_key",
            name="uq_asset_ownership_org_asset_claim",
        ),
        _organization_reference("asset_id", "assets", "fk_asset_ownership_asset_org"),
        sa.CheckConstraint(
            "owner_type IN ('TEAM', 'USER', 'BUSINESS_UNIT', 'SERVICE', 'UNKNOWN')",
            name="ck_asset_ownership_owner_type",
        ),
        sa.CheckConstraint(
            "claim_type IN ('MANUAL', 'SOURCE_ASSERTED', 'INFERRED')",
            name="ck_asset_ownership_claim_type",
        ),
        sa.CheckConstraint(
            "confidence >= 0 AND confidence <= 1",
            name="ck_asset_ownership_confidence",
        ),
    )
    op.create_index(
        "ix_asset_ownerships_organization_id",
        "asset_ownerships",
        ["organization_id"],
    )
    op.create_index("ix_asset_ownerships_asset_id", "asset_ownerships", ["asset_id"])
    op.create_index(
        "ix_asset_ownerships_asset_valid",
        "asset_ownerships",
        ["asset_id", "valid_to"],
    )
    op.create_table(
        "ownership_evidence_links",
        sa.Column("id", uuid_type, primary_key=True, nullable=False),
        sa.Column("organization_id", uuid_type, nullable=False),
        sa.Column("ownership_id", uuid_type, nullable=False),
        sa.Column("evidence_id", uuid_type, nullable=False),
        sa.Column("observation_id", uuid_type, nullable=True),
        sa.Column("relationship_type", sa.String(length=64), nullable=False),
        _timestamp("created_at"),
        _organization_reference(
            "ownership_id",
            "asset_ownerships",
            "fk_ownership_evidence_link_ownership_org",
        ),
        _organization_reference(
            "evidence_id",
            "evidence",
            "fk_ownership_evidence_link_evidence_org",
        ),
        _organization_reference(
            "observation_id",
            "canonical_observations",
            "fk_ownership_evidence_link_observation_org",
        ),
        sa.UniqueConstraint(
            "ownership_id",
            "evidence_id",
            "relationship_type",
            name="uq_ownership_evidence_link",
        ),
    )
    op.create_index(
        "ix_ownership_evidence_links_organization_id",
        "ownership_evidence_links",
        ["organization_id"],
    )
    op.create_index(
        "ix_ownership_evidence_links_ownership_id",
        "ownership_evidence_links",
        ["ownership_id"],
    )
    op.create_index(
        "ix_ownership_evidence_links_evidence_id",
        "ownership_evidence_links",
        ["evidence_id"],
    )


def downgrade() -> None:
    op.drop_table("ownership_evidence_links")
    op.drop_table("asset_ownerships")
