"""Add normalized EPSS scores.

Revision ID: 8f4c2a7d91e3
Revises: 6d3f2a1c9b84
Create Date: 2026-07-30
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "8f4c2a7d91e3"

down_revision: Union[
    str,
    Sequence[str],
    None,
] = "6d3f2a1c9b84"

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
    Crée la table centrale des derniers scores EPSS connus.
    """

    op.create_table(
        "epss_score",
        sa.Column(
            "cve_id",
            sa.String(length=32),
            nullable=False,
        ),
        sa.Column(
            "epss_score",
            postgresql.DOUBLE_PRECISION(),
            nullable=False,
        ),
        sa.Column(
            "percentile",
            postgresql.DOUBLE_PRECISION(),
            nullable=False,
        ),
        sa.Column(
            "score_date",
            sa.Date(),
            nullable=False,
        ),
        sa.Column(
            "api_version",
            sa.String(length=20),
            nullable=True,
        ),
        sa.Column(
            "synchronized_at",
            sa.DateTime(timezone=True),
            server_default=sa.text(
                "now()"
            ),
            nullable=False,
        ),
        sa.CheckConstraint(
            "cve_id ~ "
            "'^CVE-[0-9]{4}-[0-9]{4,}$'",
            name=op.f(
                "ck_epss_score_cve_id_valid"
            ),
        ),
        sa.CheckConstraint(
            "epss_score >= 0 "
            "AND epss_score <= 1",
            name=op.f(
                "ck_epss_score_epss_score_range"
            ),
        ),
        sa.CheckConstraint(
            "percentile >= 0 "
            "AND percentile <= 1",
            name=op.f(
                "ck_epss_score_percentile_range"
            ),
        ),
        sa.PrimaryKeyConstraint(
            "cve_id",
            name=op.f(
                "pk_epss_score"
            ),
        ),
        schema="normalized",
    )

    op.execute(
        sa.text(
            "GRANT SELECT, INSERT, UPDATE "
            "ON TABLE normalized.epss_score "
            "TO threat_intel_ingestion_role"
        )
    )


def downgrade() -> None:
    """
    Supprime la table centrale EPSS.
    """

    op.drop_table(
        "epss_score",
        schema="normalized",
    )