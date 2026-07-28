"""Add normalized CISA KEV vulnerabilities.

Revision ID: 1acd5f266f01
Revises: e1fe4b094ce2
Create Date: 2026-07-28 17:47:59.558269
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "1acd5f266f01"
down_revision: Union[str, Sequence[str], None] = (
    "e1fe4b094ce2"
)
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create the normalized CISA KEV persistence layer."""

    op.execute(
        sa.text(
            "CREATE SCHEMA normalized "
            "AUTHORIZATION threat_intel_owner"
        )
    )

    op.create_table(
        "cisa_kev_vulnerability",
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
            "cve_id",
            sa.String(length=32),
            nullable=False,
        ),
        sa.Column(
            "vendor_project",
            sa.String(length=255),
            nullable=False,
        ),
        sa.Column(
            "product",
            sa.String(length=255),
            nullable=False,
        ),
        sa.Column(
            "vulnerability_name",
            sa.Text(),
            nullable=False,
        ),
        sa.Column(
            "date_added",
            sa.Date(),
            nullable=False,
        ),
        sa.Column(
            "short_description",
            sa.Text(),
            nullable=False,
        ),
        sa.Column(
            "required_action",
            sa.Text(),
            nullable=False,
        ),
        sa.Column(
            "due_date",
            sa.Date(),
            nullable=False,
        ),
        sa.Column(
            "known_ransomware_campaign_use",
            sa.String(length=20),
            nullable=False,
        ),
        sa.Column(
            "notes",
            sa.Text(),
            nullable=True,
        ),
        sa.Column(
            "cwes",
            postgresql.ARRAY(
                sa.String(length=32)
            ),
            server_default=sa.text(
                "'{}'::character varying[]"
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
            "known_ransomware_campaign_use "
            "IN ('known', 'unknown')",
            name=op.f(
                "ck_cisa_kev_vulnerability_"
                "ransomware_campaign_use_valid"
            ),
        ),
        sa.ForeignKeyConstraint(
            ["raw_payload_id"],
            ["raw.source_payload.id"],
            name=op.f(
                "fk_cisa_kev_vulnerability_"
                "raw_payload_id_source_payload"
            ),
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint(
            "id",
            name=op.f(
                "pk_cisa_kev_vulnerability"
            ),
        ),
        sa.UniqueConstraint(
            "raw_payload_id",
            name="cisa_kev_raw_payload",
        ),
        schema="normalized",
    )

    op.create_index(
        "ix_cisa_kev_vulnerability_cve_id",
        "cisa_kev_vulnerability",
        ["cve_id"],
        unique=False,
        schema="normalized",
    )

    op.create_index(
        "ix_cisa_kev_vulnerability_due_date",
        "cisa_kev_vulnerability",
        ["due_date"],
        unique=False,
        schema="normalized",
    )

    op.execute(
        sa.text(
            "GRANT USAGE ON SCHEMA normalized "
            "TO threat_intel_ingestion_role"
        )
    )

    op.execute(
        sa.text(
            "GRANT SELECT, INSERT, UPDATE "
            "ON TABLE "
            "normalized.cisa_kev_vulnerability "
            "TO threat_intel_ingestion_role"
        )
    )

    op.execute(
        sa.text(
            "ALTER DEFAULT PRIVILEGES "
            "FOR ROLE threat_intel_owner "
            "IN SCHEMA normalized "
            "GRANT SELECT, INSERT, UPDATE "
            "ON TABLES "
            "TO threat_intel_ingestion_role"
        )
    )


def downgrade() -> None:
    """Remove the normalized CISA KEV persistence layer."""

    op.execute(
        sa.text(
            "ALTER DEFAULT PRIVILEGES "
            "FOR ROLE threat_intel_owner "
            "IN SCHEMA normalized "
            "REVOKE SELECT, INSERT, UPDATE "
            "ON TABLES "
            "FROM threat_intel_ingestion_role"
        )
    )

    op.drop_index(
        "ix_cisa_kev_vulnerability_due_date",
        table_name="cisa_kev_vulnerability",
        schema="normalized",
    )

    op.drop_index(
        "ix_cisa_kev_vulnerability_cve_id",
        table_name="cisa_kev_vulnerability",
        schema="normalized",
    )

    op.drop_table(
        "cisa_kev_vulnerability",
        schema="normalized",
    )

    op.execute(
        sa.text(
            "DROP SCHEMA normalized"
        )
    )