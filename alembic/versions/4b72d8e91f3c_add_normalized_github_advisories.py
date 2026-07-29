"""Add normalized GitHub advisories.

Revision ID: 4b72d8e91f3c
Revises: 9a0c1c4136df
Create Date: 2026-07-29
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "4b72d8e91f3c"

down_revision: Union[
    str,
    Sequence[str],
    None,
] = "9a0c1c4136df"

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
    Create the normalized GitHub advisory table.
    """

    op.create_table(
        "github_advisory_vulnerability",
        sa.Column(
            "id",
            sa.UUID(),
            nullable=False,
        ),
        sa.Column(
            "raw_payload_id",
            sa.UUID(),
            nullable=False,
        ),
        sa.Column(
            "ghsa_id",
            sa.String(length=32),
            nullable=False,
        ),
        sa.Column(
            "cve_id",
            sa.String(length=32),
            nullable=True,
        ),
        sa.Column(
            "advisory_type",
            sa.String(length=50),
            nullable=True,
        ),
        sa.Column(
            "severity",
            sa.String(length=20),
            nullable=True,
        ),
        sa.Column(
            "summary",
            sa.Text(),
            nullable=True,
        ),
        sa.Column(
            "description",
            sa.Text(),
            nullable=True,
        ),
        sa.Column(
            "published_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "reviewed_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "withdrawn_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "cvss_score",
            sa.Float(),
            nullable=True,
        ),
        sa.Column(
            "cvss_metrics",
            postgresql.JSONB(
                astext_type=sa.Text()
            ),
            server_default=sa.text(
                "'[]'::jsonb"
            ),
            nullable=False,
        ),
        sa.Column(
            "epss_score",
            sa.Float(),
            nullable=True,
        ),
        sa.Column(
            "epss_percentile",
            sa.Float(),
            nullable=True,
        ),
        sa.Column(
            "affected_packages",
            postgresql.JSONB(
                astext_type=sa.Text()
            ),
            server_default=sa.text(
                "'[]'::jsonb"
            ),
            nullable=False,
        ),
        sa.Column(
            "cwe_ids",
            postgresql.ARRAY(
                sa.String(length=32)
            ),
            server_default=sa.text(
                "'{}'::character varying[]"
            ),
            nullable=False,
        ),
        sa.Column(
            "references",
            postgresql.ARRAY(
                sa.Text()
            ),
            server_default=sa.text(
                "'{}'::text[]"
            ),
            nullable=False,
        ),
        sa.Column(
            "api_url",
            sa.Text(),
            nullable=True,
        ),
        sa.Column(
            "html_url",
            sa.Text(),
            nullable=True,
        ),
        sa.Column(
            "repository_advisory_url",
            sa.Text(),
            nullable=True,
        ),
        sa.Column(
            "source_code_locations",
            postgresql.ARRAY(
                sa.Text()
            ),
            server_default=sa.text(
                "'{}'::text[]"
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
            "cvss_score IS NULL OR "
            "(cvss_score >= 0 "
            "AND cvss_score <= 10)",
            name=op.f(
                "ck_github_advisory_"
                "vulnerability_cvss_score_range"
            ),
        ),
        sa.CheckConstraint(
            "epss_score IS NULL OR "
            "(epss_score >= 0 "
            "AND epss_score <= 1)",
            name=op.f(
                "ck_github_advisory_"
                "vulnerability_epss_score_range"
            ),
        ),
        sa.CheckConstraint(
            "epss_percentile IS NULL OR "
            "(epss_percentile >= 0 "
            "AND epss_percentile <= 1)",
            name=op.f(
                "ck_github_advisory_"
                "vulnerability_"
                "epss_percentile_range"
            ),
        ),
        sa.ForeignKeyConstraint(
            ["raw_payload_id"],
            ["raw.source_payload.id"],
            name=op.f(
                "fk_github_advisory_"
                "vulnerability_raw_payload_id_"
                "source_payload"
            ),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "id",
            name=op.f(
                "pk_github_advisory_"
                "vulnerability"
            ),
        ),
        sa.UniqueConstraint(
            "raw_payload_id",
            name="github_advisory_raw_payload",
        ),
        schema="normalized",
    )

    op.create_index(
        "ix_github_advisory_"
        "vulnerability_ghsa_updated",
        "github_advisory_vulnerability",
        [
            "ghsa_id",
            "updated_at",
        ],
        unique=False,
        schema="normalized",
    )

    op.create_index(
        "ix_github_advisory_"
        "vulnerability_cve_id",
        "github_advisory_vulnerability",
        ["cve_id"],
        unique=False,
        schema="normalized",
    )

    op.execute(
        sa.text(
            "GRANT SELECT, INSERT, UPDATE "
            "ON TABLE "
            "normalized."
            "github_advisory_vulnerability "
            "TO threat_intel_ingestion_role"
        )
    )


def downgrade() -> None:
    """
    Remove the normalized GitHub advisory table.
    """

    op.drop_index(
        "ix_github_advisory_"
        "vulnerability_cve_id",
        table_name=(
            "github_advisory_vulnerability"
        ),
        schema="normalized",
    )

    op.drop_index(
        "ix_github_advisory_"
        "vulnerability_ghsa_updated",
        table_name=(
            "github_advisory_vulnerability"
        ),
        schema="normalized",
    )

    op.drop_table(
        "github_advisory_vulnerability",
        schema="normalized",
    )