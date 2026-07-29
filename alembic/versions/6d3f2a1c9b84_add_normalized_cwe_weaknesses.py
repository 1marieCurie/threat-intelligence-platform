"""Add normalized CWE weaknesses.

Revision ID: 6d3f2a1c9b84
Revises: 4b72d8e91f3c
Create Date: 2026-07-29
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "6d3f2a1c9b84"

down_revision: Union[
    str,
    Sequence[str],
    None,
] = "4b72d8e91f3c"

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
    Create the normalized MITRE CWE catalog table.
    """

    op.create_table(
        "cwe_weakness",
        sa.Column(
            "cwe_id",
            sa.String(length=32),
            nullable=False,
        ),
        sa.Column(
            "name",
            sa.Text(),
            nullable=False,
        ),
        sa.Column(
            "description",
            sa.Text(),
            nullable=False,
        ),
        sa.Column(
            "abstraction",
            sa.String(length=50),
            nullable=True,
        ),
        sa.Column(
            "structure",
            sa.String(length=50),
            nullable=True,
        ),
        sa.Column(
            "status",
            sa.String(length=50),
            nullable=True,
        ),
        sa.Column(
            "extended_description",
            sa.Text(),
            nullable=True,
        ),
        sa.Column(
            "likelihood_of_exploit",
            sa.String(length=50),
            nullable=True,
        ),
        sa.Column(
            "mapping_usage",
            sa.Text(),
            nullable=True,
        ),
        sa.Column(
            "mapping_rationale",
            sa.Text(),
            nullable=True,
        ),
        sa.Column(
            "relationships",
            postgresql.JSONB(
                astext_type=sa.Text(),
            ),
            server_default=sa.text(
                "'[]'::jsonb"
            ),
            nullable=False,
        ),
        sa.Column(
            "consequences",
            postgresql.JSONB(
                astext_type=sa.Text(),
            ),
            server_default=sa.text(
                "'[]'::jsonb"
            ),
            nullable=False,
        ),
        sa.Column(
            "mitigations",
            postgresql.JSONB(
                astext_type=sa.Text(),
            ),
            server_default=sa.text(
                "'[]'::jsonb"
            ),
            nullable=False,
        ),
        sa.Column(
            "detection_methods",
            postgresql.JSONB(
                astext_type=sa.Text(),
            ),
            server_default=sa.text(
                "'[]'::jsonb"
            ),
            nullable=False,
        ),
        sa.Column(
            "applicable_platforms",
            postgresql.JSONB(
                astext_type=sa.Text(),
            ),
            server_default=sa.text(
                "'[]'::jsonb"
            ),
            nullable=False,
        ),
        sa.Column(
            "modes_of_introduction",
            postgresql.JSONB(
                astext_type=sa.Text(),
            ),
            server_default=sa.text(
                "'[]'::jsonb"
            ),
            nullable=False,
        ),
        sa.Column(
            "alternate_terms",
            postgresql.ARRAY(
                sa.Text(),
            ),
            server_default=sa.text(
                "'{}'::text[]"
            ),
            nullable=False,
        ),
        sa.Column(
            "related_capec_ids",
            postgresql.ARRAY(
                sa.String(length=32),
            ),
            server_default=sa.text(
                "'{}'::character varying[]"
            ),
            nullable=False,
        ),
        sa.Column(
            "catalog_version",
            sa.String(length=50),
            nullable=True,
        ),
        sa.Column(
            "catalog_date",
            sa.String(length=32),
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
            "cwe_id ~ '^CWE-[1-9][0-9]*$'",
            name=op.f(
                "ck_cwe_weakness_cwe_id_valid"
            ),
        ),
        sa.PrimaryKeyConstraint(
            "cwe_id",
            name=op.f(
                "pk_cwe_weakness"
            ),
        ),
        schema="normalized",
    )

    op.execute(
        sa.text(
            "GRANT SELECT, INSERT, UPDATE "
            "ON TABLE normalized.cwe_weakness "
            "TO threat_intel_ingestion_role"
        )
    )


def downgrade() -> None:
    """
    Remove the normalized CWE catalog table.
    """

    op.drop_table(
        "cwe_weakness",
        schema="normalized",
    )