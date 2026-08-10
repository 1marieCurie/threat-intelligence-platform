"""Add ML URL dataset foundation.

Revision ID: 4d6a8f2c1b90
Revises: e7cdc35dd6a0
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "4d6a8f2c1b90"
down_revision: str | Sequence[str] | None = "e7cdc35dd6a0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


ML_SCHEMA = "ml"
INGESTION_ROLE = "threat_intel_ingestion_role"

SAMPLE_TABLE = "url_sample"
PROJECTION_TABLE = "url_projection"
LABEL_TABLE = "url_sample_label"
SNAPSHOT_TABLE = "dataset_snapshot"
MEMBER_TABLE = "dataset_member"


def upgrade() -> None:
    op.execute(
        sa.text(
            "CREATE SCHEMA IF NOT EXISTS ml"
        )
    )

    op.execute(
        sa.text(
            f"GRANT USAGE ON SCHEMA ml "
            f"TO {INGESTION_ROLE}"
        )
    )

    # --------------------------------------------------------
    # URL sample identity
    # --------------------------------------------------------

    op.create_table(
        SAMPLE_TABLE,
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "canonical_web_indicator_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
        sa.Column(
            "value_hash",
            sa.String(length=64),
            nullable=False,
        ),
        sa.Column(
            "hostname",
            sa.String(length=253),
            nullable=False,
        ),
        sa.Column(
            "canonicalization_version",
            sa.Integer(),
            nullable=False,
        ),
        sa.Column(
            "source",
            sa.String(length=50),
            nullable=False,
        ),
        sa.Column(
            "source_metadata",
            postgresql.JSONB(),
            server_default=sa.text(
                "'{}'::jsonb"
            ),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "value_hash ~ '^[a-f0-9]{64}$'",
            name="ck_ml_url_sample_hash",
        ),
        sa.CheckConstraint(
            "canonicalization_version > 0",
            name="ck_ml_url_sample_version",
        ),
        sa.CheckConstraint(
            "char_length(hostname) "
            "BETWEEN 1 AND 253",
            name="ck_ml_url_sample_hostname",
        ),
        sa.CheckConstraint(
            "source ~ '^[a-z][a-z0-9_]*$'",
            name="ck_ml_url_sample_source",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(source_metadata) "
            "= 'object'",
            name="ck_ml_url_sample_metadata",
        ),
        sa.ForeignKeyConstraint(
            ["canonical_web_indicator_id"],
            [
                "canonical."
                "canonical_web_indicator.id"
            ],
            name=(
                "fk_ml_url_sample_"
                "canonical_indicator"
            ),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint(
            "id",
            name="pk_ml_url_sample",
        ),
        sa.UniqueConstraint(
            "canonicalization_version",
            "value_hash",
            name="uq_ml_url_sample_identity",
        ),
        schema=ML_SCHEMA,
    )

    op.create_index(
        "ix_ml_url_sample_hostname",
        SAMPLE_TABLE,
        ["hostname"],
        schema=ML_SCHEMA,
    )

    op.create_index(
        "ix_ml_url_sample_canonical_indicator",
        SAMPLE_TABLE,
        ["canonical_web_indicator_id"],
        schema=ML_SCHEMA,
    )

    # --------------------------------------------------------
    # Privacy-minimized model representation
    # --------------------------------------------------------

    op.create_table(
        PROJECTION_TABLE,
        sa.Column(
            "sample_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "projection_version",
            sa.String(length=30),
            nullable=False,
        ),
        sa.Column(
            "model_value",
            sa.Text(),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "char_length(projection_version) "
            "BETWEEN 1 AND 30",
            name="ck_ml_projection_version",
        ),
        sa.CheckConstraint(
            "char_length(model_value) "
            "BETWEEN 1 AND 4096",
            name="ck_ml_projection_value",
        ),
        sa.ForeignKeyConstraint(
            ["sample_id"],
            ["ml.url_sample.id"],
            name="fk_ml_projection_sample",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "sample_id",
            "projection_version",
            name="pk_ml_url_projection",
        ),
        schema=ML_SCHEMA,
    )

    # --------------------------------------------------------
    # Labels
    # --------------------------------------------------------

    op.create_table(
        LABEL_TABLE,
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "sample_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "label_code",
            sa.String(length=50),
            nullable=False,
        ),
        sa.Column(
            "label_source",
            sa.String(length=50),
            nullable=False,
        ),
        sa.Column(
            "confidence",
            sa.Numeric(
                precision=5,
                scale=4,
            ),
            nullable=False,
        ),
        sa.Column(
            "observed_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "label_code "
            "~ '^[a-z][a-z0-9_]*$'",
            name="ck_ml_label_code",
        ),
        sa.CheckConstraint(
            "label_source "
            "~ '^[a-z][a-z0-9_]*$'",
            name="ck_ml_label_source",
        ),
        sa.CheckConstraint(
            "confidence >= 0 "
            "AND confidence <= 1",
            name="ck_ml_label_confidence",
        ),
        sa.ForeignKeyConstraint(
            ["sample_id"],
            ["ml.url_sample.id"],
            name="fk_ml_label_sample",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "id",
            name="pk_ml_url_sample_label",
        ),
        sa.UniqueConstraint(
            "sample_id",
            "label_code",
            "label_source",
            name="uq_ml_sample_label_source",
        ),
        schema=ML_SCHEMA,
    )

    op.create_index(
        "ix_ml_sample_label_code",
        LABEL_TABLE,
        ["label_code"],
        schema=ML_SCHEMA,
    )

    # --------------------------------------------------------
    # Reproducible dataset snapshot
    # --------------------------------------------------------

    op.create_table(
        SNAPSHOT_TABLE,
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "name",
            sa.String(length=100),
            nullable=False,
        ),
        sa.Column(
            "version",
            sa.String(length=50),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.String(length=20),
            server_default=sa.text(
                "'draft'"
            ),
            nullable=False,
        ),
        sa.Column(
            "projection_version",
            sa.String(length=30),
            nullable=False,
        ),
        sa.Column(
            "class_targets",
            postgresql.JSONB(),
            nullable=False,
        ),
        sa.Column(
            "label_mapping",
            postgresql.JSONB(),
            nullable=False,
        ),
        sa.Column(
            "selection_config",
            postgresql.JSONB(),
            nullable=False,
        ),
        sa.Column(
            "source_manifest",
            postgresql.JSONB(),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "frozen_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.CheckConstraint(
            "status IN ('draft', 'frozen')",
            name="ck_ml_snapshot_status",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(class_targets) "
            "= 'object'",
            name="ck_ml_snapshot_targets",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(label_mapping) "
            "= 'object'",
            name="ck_ml_snapshot_mapping",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(selection_config) "
            "= 'object'",
            name="ck_ml_snapshot_config",
        ),
        sa.CheckConstraint(
            "jsonb_typeof(source_manifest) "
            "= 'object'",
            name="ck_ml_snapshot_manifest",
        ),
        sa.PrimaryKeyConstraint(
            "id",
            name="pk_ml_dataset_snapshot",
        ),
        sa.UniqueConstraint(
            "name",
            "version",
            name="uq_ml_dataset_snapshot_version",
        ),
        schema=ML_SCHEMA,
    )

    # --------------------------------------------------------
    # Snapshot membership
    # --------------------------------------------------------

    op.create_table(
        MEMBER_TABLE,
        sa.Column(
            "dataset_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "sample_id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
        ),
        sa.Column(
            "label_code",
            sa.String(length=50),
            nullable=False,
        ),
        sa.Column(
            "split",
            sa.String(length=20),
            nullable=True,
        ),
        sa.Column(
            "group_key",
            sa.String(length=253),
            nullable=False,
        ),
        sa.Column(
            "selected_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "label_code "
            "~ '^[a-z][a-z0-9_]*$'",
            name="ck_ml_member_label",
        ),
        sa.CheckConstraint(
            "split IS NULL OR split IN "
            "('train', 'validation', 'test')",
            name="ck_ml_member_split",
        ),
        sa.CheckConstraint(
            "char_length(group_key) "
            "BETWEEN 1 AND 253",
            name="ck_ml_member_group",
        ),
        sa.ForeignKeyConstraint(
            ["dataset_id"],
            ["ml.dataset_snapshot.id"],
            name="fk_ml_member_dataset",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["sample_id"],
            ["ml.url_sample.id"],
            name="fk_ml_member_sample",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "dataset_id",
            "sample_id",
            name="pk_ml_dataset_member",
        ),
        schema=ML_SCHEMA,
    )

    op.create_index(
        "ix_ml_member_label",
        MEMBER_TABLE,
        ["dataset_id", "label_code"],
        schema=ML_SCHEMA,
    )

    op.create_index(
        "ix_ml_member_group",
        MEMBER_TABLE,
        ["dataset_id", "group_key"],
        schema=ML_SCHEMA,
    )

    op.execute(
        sa.text(
            "GRANT SELECT, INSERT, UPDATE "
            "ON TABLE "
            "ml.url_sample, "
            "ml.url_projection, "
            "ml.url_sample_label, "
            "ml.dataset_snapshot, "
            "ml.dataset_member "
            f"TO {INGESTION_ROLE}"
        )
    )


def downgrade() -> None:
    op.execute(
        sa.text(
            "REVOKE ALL PRIVILEGES ON TABLE "
            "ml.url_sample, "
            "ml.url_projection, "
            "ml.url_sample_label, "
            "ml.dataset_snapshot, "
            "ml.dataset_member "
            f"FROM {INGESTION_ROLE}"
        )
    )

    op.drop_index(
        "ix_ml_member_group",
        table_name=MEMBER_TABLE,
        schema=ML_SCHEMA,
    )
    op.drop_index(
        "ix_ml_member_label",
        table_name=MEMBER_TABLE,
        schema=ML_SCHEMA,
    )

    op.drop_table(
        MEMBER_TABLE,
        schema=ML_SCHEMA,
    )
    op.drop_table(
        SNAPSHOT_TABLE,
        schema=ML_SCHEMA,
    )

    op.drop_index(
        "ix_ml_sample_label_code",
        table_name=LABEL_TABLE,
        schema=ML_SCHEMA,
    )

    op.drop_table(
        LABEL_TABLE,
        schema=ML_SCHEMA,
    )
    op.drop_table(
        PROJECTION_TABLE,
        schema=ML_SCHEMA,
    )

    op.drop_index(
        "ix_ml_url_sample_canonical_indicator",
        table_name=SAMPLE_TABLE,
        schema=ML_SCHEMA,
    )
    op.drop_index(
        "ix_ml_url_sample_hostname",
        table_name=SAMPLE_TABLE,
        schema=ML_SCHEMA,
    )

    op.drop_table(
        SAMPLE_TABLE,
        schema=ML_SCHEMA,
    )

    op.execute(
        sa.text(
            f"REVOKE USAGE ON SCHEMA ml "
            f"FROM {INGESTION_ROLE}"
        )
    )

    op.execute(
        sa.text(
            "DROP SCHEMA ml"
        )
    )