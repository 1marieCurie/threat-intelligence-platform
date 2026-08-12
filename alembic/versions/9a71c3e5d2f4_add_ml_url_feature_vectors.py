"""Add ML URL feature vectors.

Revision ID: 9a71c3e5d2f4
Revises: 4b8d55659a3d
Create Date: 2026-08-12
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "9a71c3e5d2f4"

down_revision: (
    str
    | Sequence[str]
    | None
) = "4b8d55659a3d"

branch_labels: (
    str
    | Sequence[str]
    | None
) = None

depends_on: (
    str
    | Sequence[str]
    | None
) = None


ML_SCHEMA = "ml"

FEATURE_VECTOR_TABLE = (
    "url_feature_vector"
)

SNAPSHOT_TABLE = (
    "dataset_snapshot"
)

INGESTION_ROLE = (
    "threat_intel_ingestion_role"
)


def upgrade() -> None:
    # --------------------------------------------------------
    # Feature Set version attached to a dataset snapshot.
    #
    # Nullable only for compatibility with snapshots created
    # before feature-vector persistence existed.
    # New snapshots must provide the version explicitly
    # at application level.
    # --------------------------------------------------------

    op.add_column(
        SNAPSHOT_TABLE,
        sa.Column(
            "feature_set_version",
            sa.String(
                length=30
            ),
            nullable=True,
        ),
        schema=ML_SCHEMA,
    )

    op.create_check_constraint(
        "ck_ml_snapshot_feature_set_version",
        SNAPSHOT_TABLE,
        (
            "feature_set_version IS NULL "
            "OR char_length(feature_set_version) "
            "BETWEEN 1 AND 30"
        ),
        schema=ML_SCHEMA,
    )

    # --------------------------------------------------------
    # Versioned numerical feature vectors.
    #
    # Security boundary:
    # no raw/canonical URL, hostname, query or IOC is stored
    # in this table.
    # --------------------------------------------------------

    op.create_table(
        FEATURE_VECTOR_TABLE,
        sa.Column(
            "sample_id",
            postgresql.UUID(
                as_uuid=True
            ),
            nullable=False,
        ),
        sa.Column(
            "feature_set_version",
            sa.String(
                length=30
            ),
            nullable=False,
        ),
        sa.Column(
            "features",
            postgresql.JSONB(),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(
                timezone=True
            ),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "char_length(feature_set_version) "
            "BETWEEN 1 AND 30",
            name=(
                "ck_ml_feature_vector_version"
            ),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(features) = 'object'",
            name=(
                "ck_ml_feature_vector_object"
            ),
        ),
        sa.CheckConstraint(
            "features <> '{}'::jsonb",
            name=(
                "ck_ml_feature_vector_not_empty"
            ),
        ),
        sa.ForeignKeyConstraint(
            [
                "sample_id",
            ],
            [
                "ml.url_sample.id",
            ],
            name=(
                "fk_ml_feature_vector_sample"
            ),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "sample_id",
            "feature_set_version",
            name=(
                "pk_ml_url_feature_vector"
            ),
        ),
        schema=ML_SCHEMA,
    )

    op.execute(
        sa.text(
            "GRANT SELECT, INSERT, UPDATE "
            "ON TABLE "
            "ml.url_feature_vector "
            f"TO {INGESTION_ROLE}"
        )
    )


def downgrade() -> None:
    op.execute(
        sa.text(
            "REVOKE ALL PRIVILEGES ON TABLE "
            "ml.url_feature_vector "
            f"FROM {INGESTION_ROLE}"
        )
    )

    op.drop_table(
        FEATURE_VECTOR_TABLE,
        schema=ML_SCHEMA,
    )

    op.drop_constraint(
        "ck_ml_snapshot_feature_set_version",
        SNAPSHOT_TABLE,
        schema=ML_SCHEMA,
        type_="check",
    )

    op.drop_column(
        SNAPSHOT_TABLE,
        "feature_set_version",
        schema=ML_SCHEMA,
    )