"""Add normalized HTTP Archive pages.

Revision ID: 4b8d55659a3d
Revises: 4d6a8f2c1b90
Create Date: 2026-08-11
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "4b8d55659a3d"

down_revision: (
    str
    | Sequence[str]
    | None
) = "4d6a8f2c1b90"

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


SCHEMA = "normalized"
TABLE = "http_archive_page"

INGESTION_ROLE = (
    "threat_intel_ingestion_role"
)


def upgrade() -> None:
    op.create_table(
        TABLE,

        sa.Column(
            "id",
            postgresql.UUID(
                as_uuid=True
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
            sa.String(length=64),
            nullable=False,
        ),

        sa.Column(
            "hostname",
            sa.String(length=253),
            nullable=False,
        ),

        sa.Column(
            "registered_domain",
            sa.String(length=253),
            nullable=False,
        ),

        sa.Column(
            "canonicalization_version",
            sa.Integer(),
            nullable=False,
        ),

        sa.Column(
            "source_rank",
            sa.Integer(),
            nullable=False,
        ),

        sa.Column(
            "source_snapshot",
            sa.String(length=100),
            nullable=False,
        ),

        sa.Column(
            "observed_at",
            sa.DateTime(
                timezone=True
            ),
            nullable=False,
        ),

        sa.Column(
            "normalized_at",
            sa.DateTime(
                timezone=True
            ),
            server_default=sa.func.now(),
            nullable=False,
        ),

        sa.CheckConstraint(
            "char_length(canonical_value) "
            "BETWEEN 1 AND 4096",
            name=(
                "ck_http_archive_page_"
                "canonical_value_valid"
            ),
        ),

        sa.CheckConstraint(
            "value_hash "
            "~ '^[a-f0-9]{64}$'",
            name=(
                "ck_http_archive_page_"
                "value_hash_valid"
            ),
        ),

        sa.CheckConstraint(
            "char_length(hostname) "
            "BETWEEN 1 AND 253",
            name=(
                "ck_http_archive_page_"
                "hostname_valid"
            ),
        ),

        sa.CheckConstraint(
            "char_length(registered_domain) "
            "BETWEEN 1 AND 253",
            name=(
                "ck_http_archive_page_"
                "registered_domain_valid"
            ),
        ),

        sa.CheckConstraint(
            "canonicalization_version > 0",
            name=(
                "ck_http_archive_page_"
                "canonicalization_version_positive"
            ),
        ),

        sa.CheckConstraint(
            "source_rank > 0",
            name=(
                "ck_http_archive_page_"
                "source_rank_positive"
            ),
        ),

        sa.CheckConstraint(
            "char_length(source_snapshot) "
            "BETWEEN 1 AND 100",
            name=(
                "ck_http_archive_page_"
                "source_snapshot_valid"
            ),
        ),

        sa.PrimaryKeyConstraint(
            "id",
            name=(
                "pk_http_archive_page"
            ),
        ),

        sa.UniqueConstraint(
            "source_snapshot",
            "canonicalization_version",
            "value_hash",
            name=(
                "uq_http_archive_snapshot_url"
            ),
        ),

        schema=SCHEMA,
    )

    op.create_index(
        "ix_http_archive_registered_domain",
        TABLE,
        [
            "registered_domain",
        ],
        unique=False,
        schema=SCHEMA,
    )

    op.create_index(
        "ix_http_archive_snapshot_rank",
        TABLE,
        [
            "source_snapshot",
            "source_rank",
        ],
        unique=False,
        schema=SCHEMA,
    )

    op.create_index(
        "ix_http_archive_value_hash",
        TABLE,
        [
            "value_hash",
        ],
        unique=False,
        schema=SCHEMA,
    )

    op.execute(
        sa.text(
            "GRANT SELECT, INSERT "
            "ON TABLE "
            "normalized.http_archive_page "
            f"TO {INGESTION_ROLE}"
        )
    )


def downgrade() -> None:
    op.execute(
        sa.text(
            "REVOKE ALL PRIVILEGES "
            "ON TABLE "
            "normalized.http_archive_page "
            f"FROM {INGESTION_ROLE}"
        )
    )

    op.drop_index(
        "ix_http_archive_value_hash",
        table_name=TABLE,
        schema=SCHEMA,
    )

    op.drop_index(
        "ix_http_archive_snapshot_rank",
        table_name=TABLE,
        schema=SCHEMA,
    )

    op.drop_index(
        "ix_http_archive_registered_domain",
        table_name=TABLE,
        schema=SCHEMA,
    )

    op.drop_table(
        TABLE,
        schema=SCHEMA,
    )