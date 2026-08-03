"""Add normalized URLhaus URL records.

Revision ID: a4f8c2d91e73
Revises: e7b4a2c96d10
Create Date: 2026-08-03
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "a4f8c2d91e73"

down_revision: Union[
    str,
    Sequence[str],
    None,
] = "e7b4a2c96d10"

branch_labels: Union[
    str,
    Sequence[str],
    None,
] = None

depends_on: Union[
    str,
    Sequence[str],
    None,
] = None


def upgrade() -> None:
    """
    Create the normalized URLhaus URL table.
    """

    op.create_table(
        "urlhaus_url",
        sa.Column(
            "id",
            postgresql.UUID(
                as_uuid=True
            ),
            nullable=False,
        ),
        sa.Column(
            "raw_payload_id",
            postgresql.UUID(
                as_uuid=True
            ),
            nullable=False,
        ),
        sa.Column(
            "urlhaus_id",
            sa.BigInteger(),
            nullable=False,
        ),
        sa.Column(
            "malicious_url",
            sa.Text(),
            nullable=False,
        ),
        sa.Column(
            "hostname",
            sa.String(length=253),
            nullable=False,
        ),
        sa.Column(
            "urlhaus_reference",
            sa.Text(),
            nullable=True,
        ),
        sa.Column(
            "url_status",
            sa.String(length=32),
            nullable=True,
        ),
        sa.Column(
            "date_added",
            sa.DateTime(
                timezone=True
            ),
            nullable=True,
        ),
        sa.Column(
            "threat_type",
            sa.String(length=100),
            nullable=True,
        ),
        sa.Column(
            "reporter",
            sa.String(length=255),
            nullable=True,
        ),
        sa.Column(
            "larted",
            sa.Boolean(),
            nullable=True,
        ),
        sa.Column(
            "tags",
            postgresql.JSONB(
                astext_type=sa.Text()
            ),
            server_default=sa.text(
                "'[]'::jsonb"
            ),
            nullable=False,
        ),
        sa.Column(
            "blacklists",
            postgresql.JSONB(
                astext_type=sa.Text()
            ),
            server_default=sa.text(
                "'[]'::jsonb"
            ),
            nullable=False,
        ),
        sa.Column(
            "normalizer_version",
            sa.String(length=30),
            nullable=False,
        ),
        sa.Column(
            "normalized_at",
            sa.DateTime(
                timezone=True
            ),
            server_default=sa.text(
                "now()"
            ),
            nullable=False,
        ),
        sa.CheckConstraint(
            "urlhaus_id > 0",
            name=op.f(
                "ck_urlhaus_url_"
                "urlhaus_id_positive"
            ),
        ),
        sa.CheckConstraint(
            "char_length(malicious_url) "
            "BETWEEN 1 AND 4096",
            name=op.f(
                "ck_urlhaus_url_"
                "malicious_url_length_valid"
            ),
        ),
        sa.CheckConstraint(
            "char_length(hostname) "
            "BETWEEN 1 AND 253",
            name=op.f(
                "ck_urlhaus_url_"
                "hostname_length_valid"
            ),
        ),
        sa.CheckConstraint(
            "urlhaus_reference IS NULL "
            "OR char_length(urlhaus_reference) "
            "BETWEEN 1 AND 4096",
            name=op.f(
                "ck_urlhaus_url_"
                "urlhaus_reference_length_valid"
            ),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(tags) = 'array' "
            "AND jsonb_array_length(tags) <= 100",
            name=op.f(
                "ck_urlhaus_url_"
                "tags_array_bounded"
            ),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(blacklists) = 'array' "
            "AND jsonb_array_length(blacklists) <= 50",
            name=op.f(
                "ck_urlhaus_url_"
                "blacklists_array_bounded"
            ),
        ),
        sa.CheckConstraint(
            "char_length(normalizer_version) "
            "BETWEEN 1 AND 30",
            name=op.f(
                "ck_urlhaus_url_"
                "normalizer_version_length_valid"
            ),
        ),
        sa.ForeignKeyConstraint(
            ["raw_payload_id"],
            ["raw.source_payload.id"],
            name=op.f(
                "fk_urlhaus_url_"
                "raw_payload_id_source_payload"
            ),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "id",
            name=op.f(
                "pk_urlhaus_url"
            ),
        ),
        sa.UniqueConstraint(
            "raw_payload_id",
            name="urlhaus_url_raw_payload",
        ),
        schema="normalized",
    )

    op.create_index(
        "ix_urlhaus_url_urlhaus_id",
        "urlhaus_url",
        ["urlhaus_id"],
        unique=False,
        schema="normalized",
    )

    op.create_index(
        "ix_urlhaus_url_hostname",
        "urlhaus_url",
        ["hostname"],
        unique=False,
        schema="normalized",
    )

    op.create_index(
        "ix_urlhaus_url_status",
        "urlhaus_url",
        ["url_status"],
        unique=False,
        schema="normalized",
    )

    op.create_index(
        "ix_urlhaus_url_date_added",
        "urlhaus_url",
        ["date_added"],
        unique=False,
        schema="normalized",
    )

    op.execute(
        sa.text(
            "GRANT SELECT, INSERT, UPDATE "
            "ON TABLE "
            "normalized.urlhaus_url "
            "TO threat_intel_ingestion_role"
        )
    )


def downgrade() -> None:
    """
    Remove the normalized URLhaus URL table.
    """

    op.drop_index(
        "ix_urlhaus_url_date_added",
        table_name="urlhaus_url",
        schema="normalized",
    )

    op.drop_index(
        "ix_urlhaus_url_status",
        table_name="urlhaus_url",
        schema="normalized",
    )

    op.drop_index(
        "ix_urlhaus_url_hostname",
        table_name="urlhaus_url",
        schema="normalized",
    )

    op.drop_index(
        "ix_urlhaus_url_urlhaus_id",
        table_name="urlhaus_url",
        schema="normalized",
    )

    op.drop_table(
        "urlhaus_url",
        schema="normalized",
    )