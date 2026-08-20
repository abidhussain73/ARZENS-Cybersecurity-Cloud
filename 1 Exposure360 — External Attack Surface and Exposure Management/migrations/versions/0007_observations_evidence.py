"""Create Phase 4 canonical observation and evidence records.

Revision ID: 0007_observations_evidence
Revises: 0006_asset_lifecycle
Create Date: 2026-08-20 05:45:00.000000
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "0007_observations_evidence"
down_revision = "0006_asset_lifecycle"
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
        "canonical_observations",
        sa.Column("id", uuid_type, primary_key=True, nullable=False),
        sa.Column("organization_id", uuid_type, nullable=False),
        sa.Column("asset_id", uuid_type, nullable=False),
        sa.Column("observation_type", sa.String(length=32), nullable=False),
        sa.Column("source_type", sa.String(length=64), nullable=False),
        sa.Column("source_key", sa.String(length=128), nullable=False),
        sa.Column("source_record_key", sa.String(length=512), nullable=False, server_default=""),
        sa.Column("source_version", sa.String(length=64), nullable=True),
        sa.Column("discovery_job_id", uuid_type, nullable=True),
        sa.Column("candidate_id", uuid_type, nullable=True),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        _timestamp("ingested_at"),
        sa.Column(
            "normalized_payload_json",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'{}'::json"),
        ),
        sa.Column("normalized_payload_hash", sa.String(length=64), nullable=False),
        sa.Column("idempotency_key", sa.String(length=64), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=True),
        sa.Column("state", sa.String(length=16), nullable=False, server_default="ACCEPTED"),
        _timestamp("created_at"),
        sa.UniqueConstraint(
            "id",
            "organization_id",
            name="uq_canonical_observation_id_org",
        ),
        _asset_reference(["asset_id", "organization_id"], "fk_canonical_observation_asset_org"),
        sa.ForeignKeyConstraint(
            ["discovery_job_id", "organization_id"],
            ["discovery_jobs.id", "discovery_jobs.organization_id"],
            name="fk_canonical_observation_job_org",
        ),
        sa.ForeignKeyConstraint(
            ["candidate_id", "organization_id"],
            ["candidate_assets.id", "candidate_assets.organization_id"],
            name="fk_canonical_observation_candidate_org",
        ),
        sa.UniqueConstraint(
            "organization_id",
            "idempotency_key",
            name="uq_canonical_observation_org_idempotency",
        ),
        sa.CheckConstraint(
            "observation_type IN ('DNS_A', 'DNS_AAAA', 'DNS_CNAME', "
            "'TCP_REACHABILITY', 'TLS_HANDSHAKE', 'TLS_CERTIFICATE', "
            "'HTTP_RESPONSE', 'PASSIVE_DNS_ASSOCIATION', "
            "'CERTIFICATE_METADATA', 'OWNERSHIP_ASSERTION')",
            name="ck_canonical_observation_type",
        ),
        sa.CheckConstraint(
            "state IN ('ACCEPTED', 'QUARANTINED', 'REJECTED')",
            name="ck_canonical_observation_state",
        ),
    )
    op.create_index(
        "ix_canonical_observations_organization_id",
        "canonical_observations",
        ["organization_id"],
    )
    op.create_index("ix_canonical_observations_asset_id", "canonical_observations", ["asset_id"])
    op.create_index(
        "ix_canonical_observations_asset_observed",
        "canonical_observations",
        ["asset_id", "observed_at"],
    )

    op.create_table(
        "evidence",
        sa.Column("id", uuid_type, primary_key=True, nullable=False),
        sa.Column("organization_id", uuid_type, nullable=False),
        sa.Column("observation_id", uuid_type, nullable=True),
        sa.Column("asset_id", uuid_type, nullable=False),
        sa.Column("evidence_type", sa.String(length=64), nullable=False),
        sa.Column("object_store_bucket", sa.String(length=255), nullable=False),
        sa.Column("object_store_key", sa.String(length=2048), nullable=True),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("size_bytes", sa.Integer(), nullable=False),
        sa.Column("media_type", sa.String(length=255), nullable=False),
        sa.Column("encoding", sa.String(length=64), nullable=True),
        sa.Column("source_observed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("collected_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("stored_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("retention_class", sa.String(length=64), nullable=False),
        sa.Column("sensitivity_class", sa.String(length=32), nullable=False),
        sa.Column("collector_name", sa.String(length=128), nullable=False),
        sa.Column("collector_version", sa.String(length=64), nullable=False),
        sa.Column(
            "metadata_json",
            sa.JSON(),
            nullable=False,
            server_default=sa.text("'{}'::json"),
        ),
        sa.Column("idempotency_key", sa.String(length=64), nullable=False),
        _timestamp("created_at"),
        sa.UniqueConstraint("id", "organization_id", name="uq_evidence_id_org"),
        _asset_reference(["asset_id", "organization_id"], "fk_evidence_asset_org"),
        sa.ForeignKeyConstraint(
            ["observation_id", "organization_id"],
            ["canonical_observations.id", "canonical_observations.organization_id"],
            name="fk_evidence_observation_org",
        ),
        sa.UniqueConstraint(
            "organization_id",
            "idempotency_key",
            name="uq_evidence_org_idempotency",
        ),
        sa.CheckConstraint(
            "sensitivity_class IN ('PUBLIC_METADATA', 'INTERNAL_METADATA', 'RESTRICTED')",
            name="ck_evidence_sensitivity",
        ),
    )
    op.create_index("ix_evidence_organization_id", "evidence", ["organization_id"])
    op.create_index("ix_evidence_asset_id", "evidence", ["asset_id"])
    op.create_index("ix_evidence_asset_created", "evidence", ["asset_id", "created_at"])


def downgrade() -> None:
    op.drop_table("evidence")
    op.drop_table("canonical_observations")
