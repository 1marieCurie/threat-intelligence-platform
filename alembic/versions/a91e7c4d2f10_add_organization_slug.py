"""Add organization slug for tenant login.

Revision ID: a91e7c4d2f10
Revises: 86d4692edc3c
Create Date: 2026-08-23
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "a91e7c4d2f10"

down_revision: (
    str
    | Sequence[str]
    | None
) = "86d4692edc3c"

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


SCHEMA = "threat_intel"


def upgrade() -> None:
    """Add a normalized unique slug to organizations."""

    op.add_column(
        "organization",
        sa.Column(
            "slug",
            sa.String(length=63),
            nullable=True,
        ),
        schema=SCHEMA,
    )

    op.execute(
        sa.text(
            f"""
            WITH normalized AS (
                SELECT
                    id,
                    left(
                        COALESCE(
                            NULLIF(
                                trim(
                                    both '-' from
                                    regexp_replace(
                                        lower(btrim(name)),
                                        '[^a-z0-9]+',
                                        '-',
                                        'g'
                                    )
                                ),
                                ''
                            ),
                            'organization'
                        ),
                        50
                    ) AS base_slug
                FROM {SCHEMA}.organization
            ),
            ranked AS (
                SELECT
                    id,
                    base_slug,
                    count(*) OVER (
                        PARTITION BY base_slug
                    ) AS base_count
                FROM normalized
            )
            UPDATE {SCHEMA}.organization AS organization
            SET slug = (
                CASE
                    WHEN ranked.base_count = 1
                        THEN ranked.base_slug
                    ELSE (
                        ranked.base_slug
                        || '-'
                        || substring(
                            replace(
                                organization.id::text,
                                '-',
                                ''
                            )
                            from 1 for 12
                        )
                    )
                END
            )
            FROM ranked
            WHERE organization.id = ranked.id
              AND organization.slug IS NULL
            """
        )
    )

    op.alter_column(
        "organization",
        "slug",
        existing_type=(
            sa.String(length=63)
        ),
        nullable=False,
        schema=SCHEMA,
    )

    op.create_unique_constraint(
        "uq_organization_slug",
        "organization",
        [
            "slug",
        ],
        schema=SCHEMA,
    )

    op.create_check_constraint(
        op.f(
            "ck_organization_slug_normalized"
        ),
        "organization",
        "slug = lower(btrim(slug))",
        schema=SCHEMA,
    )

    op.create_check_constraint(
        op.f(
            "ck_organization_slug_format_valid"
        ),
        "organization",
        (
            "slug ~ "
            "'^[a-z0-9]+(-[a-z0-9]+)*$'"
        ),
        schema=SCHEMA,
    )


def downgrade() -> None:
    """Remove organization tenant-login slug."""

    op.drop_constraint(
        op.f(
            "ck_organization_slug_format_valid"
        ),
        "organization",
        type_="check",
        schema=SCHEMA,
    )

    op.drop_constraint(
        op.f(
            "ck_organization_slug_normalized"
        ),
        "organization",
        type_="check",
        schema=SCHEMA,
    )

    op.drop_constraint(
        "uq_organization_slug",
        "organization",
        type_="unique",
        schema=SCHEMA,
    )

    op.drop_column(
        "organization",
        "slug",
        schema=SCHEMA,
    )