"""Add normalized PhishTank phishing records.

Revision ID: e7b4a2c96d10
Revises: c31d9a7e5b20
Create Date: 2026-08-01
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "e7b4a2c96d10"

down_revision: Union[
    str,
    Sequence[str],
    None,
] = "c31d9a7e5b20"

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
    Create the normalized PhishTank phishing table.
    """

    op.create_table(
        "phishtank_phishing",
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
            "phish_id",
            sa.BigInteger(),
            nullable=False,
        ),
        sa.Column(
            "phishing_url",
            sa.Text(),
            nullable=False,
        ),
        sa.Column(
            "hostname",
            sa.String(length=253),
            nullable=False,
        ),
        sa.Column(
            "phish_detail_url",
            sa.Text(),
            nullable=True,
        ),
        sa.Column(
            "submission_time",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "verification_time",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "verified",
            sa.Boolean(),
            nullable=True,
        ),
        sa.Column(
            "online",
            sa.Boolean(),
            nullable=True,
        ),
        sa.Column(
            "target",
            sa.String(length=255),
            nullable=True,
        ),
        sa.Column(
            "network_details",
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
            sa.DateTime(timezone=True),
            server_default=sa.text(
                "now()"
            ),
            nullable=False,
        ),
        sa.CheckConstraint(
            "phish_id > 0",
            name=op.f(
                "ck_phishtank_phishing_"
                "phish_id_positive"
            ),
        ),
        sa.CheckConstraint(
            "char_length(phishing_url) "
            "BETWEEN 1 AND 4096",
            name=op.f(
                "ck_phishtank_phishing_"
                "phishing_url_length_valid"
            ),
        ),
        sa.CheckConstraint(
            "char_length(hostname) "
            "BETWEEN 1 AND 253",
            name=op.f(
                "ck_phishtank_phishing_"
                "hostname_length_valid"
            ),
        ),
        sa.CheckConstraint(
            "jsonb_typeof(network_details) "
            "= 'array'",
            name=op.f(
                "ck_phishtank_phishing_"
                "network_details_array"
            ),
        ),
        sa.CheckConstraint(
            "verification_time IS NULL "
            "OR submission_time IS NULL "
            "OR verification_time "
            ">= submission_time",
            name=op.f(
                "ck_phishtank_phishing_"
                "verification_time_order"
            ),
        ),
        sa.ForeignKeyConstraint(
            ["raw_payload_id"],
            ["raw.source_payload.id"],
            name=op.f(
                "fk_phishtank_phishing_"
                "raw_payload_id_source_payload"
            ),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "id",
            name=op.f(
                "pk_phishtank_phishing"
            ),
        ),
        sa.UniqueConstraint(
            "raw_payload_id",
            name=(
                "phishtank_phishing_"
                "raw_payload"
            ),
        ),
        schema="normalized",
    )

    op.create_index(
        "ix_phishtank_phishing_phish_id",
        "phishtank_phishing",
        ["phish_id"],
        unique=False,
        schema="normalized",
    )

    op.create_index(
        "ix_phishtank_phishing_hostname",
        "phishtank_phishing",
        ["hostname"],
        unique=False,
        schema="normalized",
    )

    op.create_index(
        "ix_phishtank_phishing_status",
        "phishtank_phishing",
        [
            "verified",
            "online",
        ],
        unique=False,
        schema="normalized",
    )

    op.execute(
        sa.text(
            "GRANT SELECT, INSERT, UPDATE "
            "ON TABLE "
            "normalized.phishtank_phishing "
            "TO threat_intel_ingestion_role"
        )
    )


def downgrade() -> None:
    """
    Remove the normalized PhishTank phishing table.
    """

    op.drop_index(
        "ix_phishtank_phishing_status",
        table_name="phishtank_phishing",
        schema="normalized",
    )

    op.drop_index(
        "ix_phishtank_phishing_hostname",
        table_name="phishtank_phishing",
        schema="normalized",
    )

    op.drop_index(
        "ix_phishtank_phishing_phish_id",
        table_name="phishtank_phishing",
        schema="normalized",
    )

    op.drop_table(
        "phishtank_phishing",
        schema="normalized",
    )