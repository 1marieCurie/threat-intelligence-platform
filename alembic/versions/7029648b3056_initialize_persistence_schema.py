"""initialize persistence schema

Revision ID: 7029648b3056
Revises: 
Create Date: 2026-07-23 19:52:04.272373

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '7029648b3056'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "persistence_healthcheck",
        sa.Column(
            "id",
            sa.Integer(),
            primary_key=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        schema="threat_intel",
    )


def downgrade() -> None:
    op.drop_table(
        "persistence_healthcheck",
        schema="threat_intel",
    )
