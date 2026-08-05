"""Add canonical Web indicators.

Revision ID: 817d8fdb14cd
Revises: f3a8c2d71b94
Create Date: 2026-08-05 19:55:26.299195
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "817d8fdb14cd"

down_revision: str | Sequence[str] | None = (
    "f3a8c2d71b94"
)

branch_labels: str | Sequence[str] | None = None

depends_on: str | Sequence[str] | None = None


CANONICAL_SCHEMA = "canonical"

INGESTION_ROLE = (
    "threat_intel_ingestion_role"
)

INDICATOR_TABLE = (
    "canonical_web_indicator"
)

OBSERVATION_TABLE = (
    "canonical_web_indicator_observation"
)


def upgrade() -> None:
    """
    Create canonical Web indicator persistence.

    Correlation remains strictly based on the versioned
    canonical URL hash. Hostname is indexed for reading only
    and never acts as a correlation key.
    """
    op.create_table(
        INDICATOR_TABLE,
        sa.Column(
            "id",
            postgresql.UUID(
                as_uuid=True,
            ),
            nullable=False,
        ),
        sa.Column(
            "indicator_type",
            sa.String(
                length=16,
            ),
            server_default=sa.text(
                "'url'"
            ),
            nullable=False,
        ),
        sa.Column(
            "canonical_value",
            sa.Text(),
            nullable=False,
        ),
        sa.Column(
            "value_hash",
            sa.String(
                length=64,
            ),
            nullable=False,
        ),
        sa.Column(
            "hostname",
            sa.String(
                length=253,
            ),
            nullable=False,
        ),
        sa.Column(
            "canonicalization_version",
            sa.Integer(),
            server_default=sa.text(
                "1"
            ),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(
                timezone=True,
            ),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(
                timezone=True,
            ),
            nullable=False,
        ),
        sa.CheckConstraint(
            "indicator_type = 'url'",
            name=op.f(
                "ck_canonical_web_indicator_"
                "indicator_type_url"
            ),
        ),
        sa.CheckConstraint(
            "value_hash ~ '^[a-f0-9]{64}$'",
            name=op.f(
                "ck_canonical_web_indicator_"
                "value_hash_sha256"
            ),
        ),
        sa.CheckConstraint(
            "canonicalization_version > 0",
            name=op.f(
                "ck_canonical_web_indicator_"
                "canonicalization_version_positive"
            ),
        ),
        sa.CheckConstraint(
            "char_length(canonical_value) "
            "BETWEEN 1 AND 4096",
            name=op.f(
                "ck_canonical_web_indicator_"
                "canonical_value_length_valid"
            ),
        ),
        sa.CheckConstraint(
            "char_length(hostname) "
            "BETWEEN 1 AND 253",
            name=op.f(
                "ck_canonical_web_indicator_"
                "hostname_length_valid"
            ),
        ),
        sa.CheckConstraint(
            "updated_at >= created_at",
            name=op.f(
                "ck_canonical_web_indicator_"
                "timestamps_order"
            ),
        ),
        sa.PrimaryKeyConstraint(
            "id",
            name=op.f(
                "pk_canonical_web_indicator"
            ),
        ),
        sa.UniqueConstraint(
            "canonicalization_version",
            "value_hash",
            name=(
                "canonical_web_indicator_"
                "version_value_hash"
            ),
        ),
        schema=CANONICAL_SCHEMA,
    )

    op.create_index(
        "ix_canonical_web_indicator_hostname",
        INDICATOR_TABLE,
        [
            "hostname",
        ],
        unique=False,
        schema=CANONICAL_SCHEMA,
    )

    op.create_index(
        "ix_canonical_web_indicator_updated_at",
        INDICATOR_TABLE,
        [
            "updated_at",
        ],
        unique=False,
        schema=CANONICAL_SCHEMA,
    )

    op.create_table(
        OBSERVATION_TABLE,
        sa.Column(
            "id",
            postgresql.UUID(
                as_uuid=True,
            ),
            nullable=False,
        ),
        sa.Column(
            "indicator_id",
            postgresql.UUID(
                as_uuid=True,
            ),
            nullable=False,
        ),
        sa.Column(
            "source",
            sa.String(
                length=50,
            ),
            nullable=False,
        ),
        sa.Column(
            "source_record_key",
            sa.String(
                length=255,
            ),
            nullable=False,
        ),
        sa.Column(
            "normalized_record_id",
            postgresql.UUID(
                as_uuid=True,
            ),
            nullable=False,
        ),
        sa.Column(
            "observed_at",
            sa.DateTime(
                timezone=True,
            ),
            nullable=False,
        ),
        sa.Column(
            "last_observed_at",
            sa.DateTime(
                timezone=True,
            ),
            nullable=False,
        ),
        sa.Column(
            "normalizer_version",
            sa.String(
                length=30,
            ),
            nullable=False,
        ),
        sa.Column(
            "source_status",
            sa.String(
                length=64,
            ),
            nullable=True,
        ),
        sa.Column(
            "is_active",
            sa.Boolean(),
            nullable=True,
        ),
        sa.Column(
            "labels",
            postgresql.JSONB(
                astext_type=sa.Text(),
            ),
            server_default=sa.text(
                "'[]'::jsonb"
            ),
            nullable=False,
        ),
        sa.CheckConstraint(
            "btrim(source_record_key) <> ''",
            name=op.f(
                "ck_canonical_web_indicator_"
                "observation_source_record_key_"
                "not_empty"
            ),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(labels) = 'array' "
            "AND jsonb_array_length(labels) <= 20",
            name=op.f(
                "ck_canonical_web_indicator_"
                "observation_labels_array_bounded"
            ),
        ),
        sa.CheckConstraint(
            "source ~ '^[a-z][a-z0-9_]*$'",
            name=op.f(
                "ck_canonical_web_indicator_"
                "observation_source_format_valid"
            ),
        ),
        sa.CheckConstraint(
            "source_status IS NULL "
            "OR source_status "
            "~ '^[a-z][a-z0-9_]*$'",
            name=op.f(
                "ck_canonical_web_indicator_"
                "observation_source_status_"
                "format_valid"
            ),
        ),
        sa.CheckConstraint(
            "char_length(normalizer_version) "
            "BETWEEN 1 AND 30",
            name=op.f(
                "ck_canonical_web_indicator_"
                "observation_normalizer_version_"
                "length_valid"
            ),
        ),
        sa.CheckConstraint(
            "last_observed_at >= observed_at",
            name=op.f(
                "ck_canonical_web_indicator_"
                "observation_observation_dates_order"
            ),
        ),
        sa.ForeignKeyConstraint(
            [
                "indicator_id",
            ],
            [
                (
                    "canonical."
                    "canonical_web_indicator.id"
                ),
            ],
            name=op.f(
                "fk_canonical_web_indicator_"
                "observation_indicator_id_"
                "canonical_web_indicator"
            ),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "id",
            name=op.f(
                "pk_canonical_web_indicator_"
                "observation"
            ),
        ),
        sa.UniqueConstraint(
            "source",
            "source_record_key",
            name=(
                "canonical_web_observation_"
                "source_record"
            ),
        ),
        schema=CANONICAL_SCHEMA,
    )

    op.create_index(
        "ix_canonical_web_observation_indicator_id",
        OBSERVATION_TABLE,
        [
            "indicator_id",
        ],
        unique=False,
        schema=CANONICAL_SCHEMA,
    )

    op.create_index(
        "ix_canonical_web_observation_"
        "last_observed_at",
        OBSERVATION_TABLE,
        [
            "last_observed_at",
        ],
        unique=False,
        schema=CANONICAL_SCHEMA,
    )

    op.create_index(
        "ix_canonical_web_observation_"
        "normalized_record_id",
        OBSERVATION_TABLE,
        [
            "normalized_record_id",
        ],
        unique=False,
        schema=CANONICAL_SCHEMA,
    )

    # Le rôle applicatif peut corréler et enrichir les
    # observations, sans disposer de droits de suppression
    # ou de modification du schéma.
    op.execute(
        sa.text(
            "GRANT SELECT, INSERT, UPDATE "
            "ON TABLE "
            "canonical.canonical_web_indicator, "
            "canonical."
            "canonical_web_indicator_observation "
            f"TO {INGESTION_ROLE}"
        )
    )


def downgrade() -> None:
    """
    Remove canonical Web indicator persistence.

    Les permissions sont retirées avant la suppression
    des tables.
    """
    op.execute(
        sa.text(
            "REVOKE ALL PRIVILEGES "
            "ON TABLE "
            "canonical.canonical_web_indicator, "
            "canonical."
            "canonical_web_indicator_observation "
            f"FROM {INGESTION_ROLE}"
        )
    )

    op.drop_index(
        "ix_canonical_web_observation_"
        "normalized_record_id",
        table_name=OBSERVATION_TABLE,
        schema=CANONICAL_SCHEMA,
    )

    op.drop_index(
        "ix_canonical_web_observation_"
        "last_observed_at",
        table_name=OBSERVATION_TABLE,
        schema=CANONICAL_SCHEMA,
    )

    op.drop_index(
        "ix_canonical_web_observation_indicator_id",
        table_name=OBSERVATION_TABLE,
        schema=CANONICAL_SCHEMA,
    )

    op.drop_table(
        OBSERVATION_TABLE,
        schema=CANONICAL_SCHEMA,
    )

    op.drop_index(
        "ix_canonical_web_indicator_updated_at",
        table_name=INDICATOR_TABLE,
        schema=CANONICAL_SCHEMA,
    )

    op.drop_index(
        "ix_canonical_web_indicator_hostname",
        table_name=INDICATOR_TABLE,
        schema=CANONICAL_SCHEMA,
    )

    op.drop_table(
        INDICATOR_TABLE,
        schema=CANONICAL_SCHEMA,
    )