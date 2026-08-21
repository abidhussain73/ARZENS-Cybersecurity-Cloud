"""Create Phase 6 external-context and relationship graph tables.

Revision ID: 0018_relationship_graph
Revises: 0017_evaluation_runs
"""

import sqlalchemy as sa
from alembic import op

revision = "0018_relationship_graph"
down_revision = "0017_evaluation_runs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "external_context_entities",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("context_type", sa.String(length=32), nullable=False),
        sa.Column("canonical_key", sa.String(length=2048), nullable=False),
        sa.Column("display_name", sa.String(length=2048), nullable=False),
        sa.Column("source_namespace", sa.String(length=128), nullable=False),
        sa.Column("source_native_id", sa.String(length=512), nullable=True),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "context_type IN ('IDENTITY', 'CLOUD_RESOURCE', 'APPLICATION', 'DATA', "
            "'VULNERABILITY')",
            name="ck_external_context_entity_type",
        ),
        sa.CheckConstraint(
            "confidence >= 0 AND confidence <= 1", name="ck_external_context_entity_confidence"
        ),
        sa.CheckConstraint(
            "state IN ('ACTIVE', 'STALE', 'ENDED', 'INVALID')",
            name="ck_external_context_entity_state",
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("id", "organization_id", name="uq_external_context_entity_id_org"),
        sa.UniqueConstraint(
            "organization_id",
            "context_type",
            "canonical_key",
            name="uq_external_context_entity_org_type_key",
        ),
    )
    op.create_index(
        "ix_external_context_entities_org_type_seen",
        "external_context_entities",
        ["organization_id", "context_type", "last_seen"],
    )
    op.create_table(
        "relationships",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("relationship_type", sa.String(length=128), nullable=False),
        sa.Column("source_asset_id", sa.UUID(), nullable=True),
        sa.Column("source_context_entity_id", sa.UUID(), nullable=True),
        sa.Column("target_asset_id", sa.UUID(), nullable=True),
        sa.Column("target_context_entity_id", sa.UUID(), nullable=True),
        sa.Column("canonical_key", sa.String(length=64), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("confidence_model_version", sa.String(length=64), nullable=False),
        sa.Column("registry_version", sa.String(length=64), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_to", sa.DateTime(timezone=True), nullable=True),
        sa.Column("state", sa.String(length=16), nullable=False),
        sa.Column("source_system", sa.String(length=128), nullable=False),
        sa.Column("source_record_key", sa.String(length=512), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "(source_asset_id IS NOT NULL AND source_context_entity_id IS NULL) OR "
            "(source_asset_id IS NULL AND source_context_entity_id IS NOT NULL)",
            name="ck_relationship_one_source_endpoint",
        ),
        sa.CheckConstraint(
            "(target_asset_id IS NOT NULL AND target_context_entity_id IS NULL) OR "
            "(target_asset_id IS NULL AND target_context_entity_id IS NOT NULL)",
            name="ck_relationship_one_target_endpoint",
        ),
        sa.CheckConstraint(
            "confidence >= 0 AND confidence <= 1", name="ck_relationship_confidence"
        ),
        sa.CheckConstraint(
            "valid_to IS NULL OR valid_from < valid_to", name="ck_relationship_valid_window"
        ),
        sa.CheckConstraint(
            "state IN ('ACTIVE', 'STALE', 'ENDED', 'INVALID')", name="ck_relationship_state"
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"]),
        sa.ForeignKeyConstraint(
            ["source_asset_id", "organization_id"],
            ["assets.id", "assets.organization_id"],
            name="fk_relationship_source_asset_org",
        ),
        sa.ForeignKeyConstraint(
            ["target_asset_id", "organization_id"],
            ["assets.id", "assets.organization_id"],
            name="fk_relationship_target_asset_org",
        ),
        sa.ForeignKeyConstraint(
            ["source_context_entity_id", "organization_id"],
            ["external_context_entities.id", "external_context_entities.organization_id"],
            name="fk_relationship_source_context_org",
        ),
        sa.ForeignKeyConstraint(
            ["target_context_entity_id", "organization_id"],
            ["external_context_entities.id", "external_context_entities.organization_id"],
            name="fk_relationship_target_context_org",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("id", "organization_id", name="uq_relationship_id_org"),
        sa.UniqueConstraint(
            "organization_id", "canonical_key", name="uq_relationship_org_canonical_key"
        ),
    )
    for name, columns in (
        (
            "ix_relationships_org_source_asset_state",
            ["organization_id", "source_asset_id", "state"],
        ),
        (
            "ix_relationships_org_target_asset_state",
            ["organization_id", "target_asset_id", "state"],
        ),
        (
            "ix_relationships_org_source_context_state",
            ["organization_id", "source_context_entity_id", "state"],
        ),
        (
            "ix_relationships_org_target_context_state",
            ["organization_id", "target_context_entity_id", "state"],
        ),
        ("ix_relationships_org_type_state", ["organization_id", "relationship_type", "state"]),
        ("ix_relationships_org_valid_window", ["organization_id", "valid_from", "valid_to"]),
    ):
        op.create_index(name, "relationships", columns)
    op.create_table(
        "relationship_evidence_links",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("organization_id", sa.UUID(), nullable=False),
        sa.Column("relationship_id", sa.UUID(), nullable=False),
        sa.Column("observation_id", sa.UUID(), nullable=True),
        sa.Column("evidence_id", sa.UUID(), nullable=True),
        sa.Column("source_context_record_hash", sa.String(length=64), nullable=True),
        sa.Column("link_key", sa.String(length=64), nullable=False),
        sa.Column(
            "linked_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.CheckConstraint(
            "observation_id IS NOT NULL OR evidence_id IS NOT NULL OR "
            "source_context_record_hash IS NOT NULL",
            name="ck_relationship_evidence_link_provenance",
        ),
        sa.ForeignKeyConstraint(
            ["relationship_id", "organization_id"],
            ["relationships.id", "relationships.organization_id"],
            name="fk_relationship_evidence_link_relationship_org",
        ),
        sa.ForeignKeyConstraint(
            ["observation_id", "organization_id"],
            ["canonical_observations.id", "canonical_observations.organization_id"],
            name="fk_relationship_evidence_link_observation_org",
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id", "organization_id"],
            ["evidence.id", "evidence.organization_id"],
            name="fk_relationship_evidence_link_evidence_org",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id", "link_key", name="uq_relationship_evidence_link_org_key"
        ),
    )


def downgrade() -> None:
    op.drop_table("relationship_evidence_links")
    op.drop_table("relationships")
    op.drop_table("external_context_entities")
