"""Add raw payload processing lease.

Revision ID: 9a0c1c4136df
Revises: 1acd5f266f01
Create Date: 2026-07-28 18:51:38.027742
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "9a0c1c4136df"
down_revision: Union[str, Sequence[str], None] = (
    "1acd5f266f01"
)
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add processing lease metadata to raw payloads."""

    op.add_column(
        "source_payload",
        sa.Column(
            "processing_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        schema="raw",
    )

    op.add_column(
        "source_payload",
        sa.Column(
            "processing_attempts",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        schema="raw",
    )

    op.create_check_constraint(
        "ck_source_payload_processing_attempts_non_negative",
        "source_payload",
        "processing_attempts >= 0",
        schema="raw",
    )

    # Les anciennes lignes processing ne possèdent aucune
    # date de début. Elles sont remises en attente afin de
    # pouvoir être reprises proprement.
    op.execute(
        sa.text(
            """
            UPDATE raw.source_payload
            SET processing_status = 'pending'
            WHERE processing_status = 'processing'
              AND processing_started_at IS NULL
            """
        )
    )

    op.create_index(
        "ix_source_payload_processing_lease",
        "source_payload",
        [
            "source_id",
            "processing_started_at",
        ],
        unique=False,
        schema="raw",
        postgresql_where=sa.text(
            "processing_status = 'processing'"
        ),
    )


def downgrade() -> None:
    """Remove processing lease metadata from raw payloads."""

    op.drop_index(
        "ix_source_payload_processing_lease",
        table_name="source_payload",
        schema="raw",
    )

    op.drop_constraint(
        "ck_source_payload_processing_attempts_non_negative",
        "source_payload",
        schema="raw",
        type_="check",
    )

    op.drop_column(
        "source_payload",
        "processing_attempts",
        schema="raw",
    )

    op.drop_column(
        "source_payload",
        "processing_started_at",
        schema="raw",
    )