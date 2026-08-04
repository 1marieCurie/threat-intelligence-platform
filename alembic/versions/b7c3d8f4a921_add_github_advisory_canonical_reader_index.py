"""Optimize GitHub advisory canonical keyset reads.

Revision ID: b7c3d8f4a921
Revises: e91a4c7b2d30
Create Date: 2026-08-04
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op


revision: str = "b7c3d8f4a921"

down_revision: (
    str
    | Sequence[str]
    | None
) = "e91a4c7b2d30"

branch_labels: (
    str
    | Sequence[str]
    | None
) = None

depends_on: (
    str
    | Sequence[str]
    | None
) = None


def upgrade() -> None:
    op.create_index(
        (
            "ix_github_advisory_"
            "vulnerability_ghsa_id_id"
        ),
        "github_advisory_vulnerability",
        [
            "ghsa_id",
            "id",
        ],
        unique=False,
        schema="normalized",
    )


def downgrade() -> None:
    op.drop_index(
        (
            "ix_github_advisory_"
            "vulnerability_ghsa_id_id"
        ),
        table_name=(
            "github_advisory_vulnerability"
        ),
        schema="normalized",
    )