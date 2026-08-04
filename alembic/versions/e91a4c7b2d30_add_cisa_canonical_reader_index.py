"""Optimize CISA KEV canonical keyset reads.

Revision ID: e91a4c7b2d30
Revises: c7e2f9a41b6d
Create Date: 2026-08-04
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op


revision: str = "e91a4c7b2d30"

down_revision: (
    str
    | Sequence[str]
    | None
) = "c7e2f9a41b6d"

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
    op.drop_index(
        "ix_cisa_kev_vulnerability_cve_id",
        table_name=(
            "cisa_kev_vulnerability"
        ),
        schema="normalized",
    )

    op.create_index(
        (
            "ix_cisa_kev_vulnerability_"
            "cve_id_id"
        ),
        "cisa_kev_vulnerability",
        [
            "cve_id",
            "id",
        ],
        unique=False,
        schema="normalized",
    )


def downgrade() -> None:
    op.drop_index(
        (
            "ix_cisa_kev_vulnerability_"
            "cve_id_id"
        ),
        table_name=(
            "cisa_kev_vulnerability"
        ),
        schema="normalized",
    )

    op.create_index(
        "ix_cisa_kev_vulnerability_cve_id",
        "cisa_kev_vulnerability",
        [
            "cve_id",
        ],
        unique=False,
        schema="normalized",
    )