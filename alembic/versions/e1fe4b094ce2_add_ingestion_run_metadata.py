"""Add ingestion run metadata.

Revision ID: e1fe4b094ce2
Revises: 7d946e3df087
Create Date: 2026-07-28 16:10:31.579641
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# Revision identifiers, used by Alembic.
revision: str = "e1fe4b094ce2"
down_revision: Union[str, Sequence[str], None] = (
    "7d946e3df087"
)
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add immutable metadata to ingestion runs."""

    op.add_column(
        "ingestion_run",
        sa.Column(
            "metadata",
            postgresql.JSONB(),
            server_default=sa.text(
                "'{}'::jsonb"
            ),
            nullable=False,
        ),
        schema="ops",
    )


def downgrade() -> None:
    """Remove ingestion run metadata."""

    op.drop_column(
        "ingestion_run",
        "metadata",
        schema="ops",
    )