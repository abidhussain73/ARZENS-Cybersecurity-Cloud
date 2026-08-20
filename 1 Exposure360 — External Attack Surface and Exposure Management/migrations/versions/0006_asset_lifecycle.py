"""Create versioned Phase 4 canonical asset freshness policies.

Revision ID: 0006_asset_lifecycle
Revises: 0005_canonical_assets
Create Date: 2026-08-20 05:40:00.000000
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0006_asset_lifecycle"
down_revision = "0005_canonical_assets"
branch_labels = None
depends_on = None


def upgrade() -> None:
    uuid_type = postgresql.UUID(as_uuid=True)
    op.create_table(
        "asset_freshness_policies",
        sa.Column("id", uuid_type, primary_key=True, nullable=False),
        sa.Column("organization_id", uuid_type, sa.ForeignKey("organizations.id"), nullable=False),
        sa.Column("asset_type", sa.String(length=16), nullable=False),
        sa.Column("policy_version", sa.String(length=64), nullable=False),
        sa.Column("stale_after_seconds", sa.Integer(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.UniqueConstraint(
            "organization_id",
            "asset_type",
            "policy_version",
            name="uq_asset_freshness_policy_org_type_version",
        ),
        sa.CheckConstraint(
            "asset_type IN ('DOMAIN', 'IP', 'ASN', 'ENDPOINT', 'SERVICE')",
            name="ck_asset_freshness_policy_type",
        ),
        sa.CheckConstraint("stale_after_seconds > 0", name="ck_asset_freshness_policy_seconds"),
    )
    op.create_index(
        "ix_asset_freshness_policies_organization_id",
        "asset_freshness_policies",
        ["organization_id"],
    )
    op.create_index(
        "ix_asset_freshness_policy_org_type_active",
        "asset_freshness_policies",
        ["organization_id", "asset_type", "is_active"],
    )


def downgrade() -> None:
    op.drop_table("asset_freshness_policies")
