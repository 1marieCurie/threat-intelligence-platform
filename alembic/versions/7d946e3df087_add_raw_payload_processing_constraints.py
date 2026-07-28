"""add raw payload processing constraints

Revision ID: 7d946e3df087
Revises: f67768883d74
Create Date: 2026-07-28 14:50:43.674869
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "7d946e3df087"
down_revision: Union[str, Sequence[str], None] = "f67768883d74"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add raw payload processing constraints and claim index."""

    op.create_check_constraint(
        "processing_status_valid",
        "source_payload",
        (
            "processing_status IN "
            "('pending', 'processing', 'processed', 'failed')"
        ),
        schema="raw",
    )

    op.create_index(
        "ix_source_payload_pending_claim",
        "source_payload",
        [
            "source_id",
            "retrieved_at",
            "id",
        ],
        unique=False,
        schema="raw",
        postgresql_where=sa.text(
            "processing_status = 'pending'"
        ),
    )


def downgrade() -> None:
    """Remove raw payload processing constraints and claim index."""

    op.drop_index(
        "ix_source_payload_pending_claim",
        table_name="source_payload",
        schema="raw",
    )

    op.drop_constraint(
        "processing_status_valid",
        "source_payload",
        schema="raw",
        type_="check",
    )