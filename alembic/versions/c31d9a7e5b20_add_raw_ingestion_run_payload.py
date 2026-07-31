"""Add raw ingestion run payload links.

Revision ID: c31d9a7e5b20
Revises: 8f4c2a7d91e3
Create Date: 2026-07-31
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "c31d9a7e5b20"

down_revision: Union[
    str,
    Sequence[str],
    None,
] = "8f4c2a7d91e3"

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
    Crée la relation entre un run d'ingestion et tous les
    payloads observés pendant son snapshot.
    """
    op.create_table(
        "ingestion_run_payload",
        sa.Column(
            "ingestion_run_id",
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
            "observed_at",
            sa.DateTime(
                timezone=True
            ),
            server_default=sa.text(
                "now()"
            ),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            [
                "ingestion_run_id",
            ],
            [
                "ops.ingestion_run.id",
            ],
            name=op.f(
                "fk_ingestion_run_payload_"
                "ingestion_run_id_ingestion_run"
            ),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            [
                "raw_payload_id",
            ],
            [
                "raw.source_payload.id",
            ],
            name=op.f(
                "fk_ingestion_run_payload_"
                "raw_payload_id_source_payload"
            ),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "ingestion_run_id",
            "raw_payload_id",
            name=op.f(
                "pk_ingestion_run_payload"
            ),
        ),
        schema="raw",
    )

    op.create_index(
        op.f(
            "ix_ingestion_run_payload_"
            "raw_payload_id"
        ),
        "ingestion_run_payload",
        [
            "raw_payload_id",
        ],
        unique=False,
        schema="raw",
    )

    op.execute(
        sa.text(
            "GRANT SELECT, INSERT, DELETE "
            "ON TABLE "
            "raw.ingestion_run_payload "
            "TO threat_intel_ingestion_role"
        )
    )


def downgrade() -> None:
    """
    Supprime la relation run/payload.
    """
    op.drop_index(
        op.f(
            "ix_ingestion_run_payload_"
            "raw_payload_id"
        ),
        table_name=(
            "ingestion_run_payload"
        ),
        schema="raw",
    )

    op.drop_table(
        "ingestion_run_payload",
        schema="raw",
    )