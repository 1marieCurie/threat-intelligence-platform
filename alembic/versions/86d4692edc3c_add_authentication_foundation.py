"""Add authentication foundation.

Revision ID: 86d4692edc3c
Revises: d2f1a6b7c9e0
Create Date: 2026-08-21
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "86d4692edc3c"

down_revision: (
    str
    | Sequence[str]
    | None
) = "d2f1a6b7c9e0"

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

_DISABLED_PASSWORD_HASH = (
    "!authentication-not-configured!"
)


def upgrade() -> None:
    """Add password credentials and refresh-token sessions."""

    _add_password_hash()
    _create_auth_session_table()


def downgrade() -> None:
    """Remove authentication persistence."""

    op.drop_index(
        "ix_auth_session_expires_at",
        table_name="auth_session",
        schema=SCHEMA,
    )

    op.drop_index(
        "ix_auth_session_user_id",
        table_name="auth_session",
        schema=SCHEMA,
    )

    op.drop_index(
        "ix_auth_session_organization_id",
        table_name="auth_session",
        schema=SCHEMA,
    )

    op.drop_table(
        "auth_session",
        schema=SCHEMA,
    )

    op.drop_column(
        "user_account",
        "password_hash",
        schema=SCHEMA,
    )


def _add_password_hash() -> None:
    op.add_column(
        "user_account",
        sa.Column(
            "password_hash",
            sa.String(length=512),
            nullable=True,
        ),
        schema=SCHEMA,
    )

    op.execute(
        sa.text(
            f"""
            UPDATE {SCHEMA}.user_account
            SET password_hash = :disabled_hash
            WHERE password_hash IS NULL
            """
        ).bindparams(
            disabled_hash=(
                _DISABLED_PASSWORD_HASH
            )
        )
    )

    op.alter_column(
        "user_account",
        "password_hash",
        existing_type=(
            sa.String(length=512)
        ),
        nullable=False,
        schema=SCHEMA,
    )

    op.create_check_constraint(
        "ck_user_account_password_hash_not_blank",
        "user_account",
        (
            "char_length("
            "btrim(password_hash)"
            ") > 0"
        ),
        schema=SCHEMA,
    )


def _create_auth_session_table() -> None:
    op.create_table(
        "auth_session",
        sa.Column(
            "id",
            postgresql.UUID(
                as_uuid=True
            ),
            nullable=False,
        ),
        sa.Column(
            "organization_id",
            postgresql.UUID(
                as_uuid=True
            ),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            postgresql.UUID(
                as_uuid=True
            ),
            nullable=False,
        ),
        sa.Column(
            "refresh_token_hash",
            sa.String(
                length=64
            ),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(
                timezone=True
            ),
            nullable=False,
        ),
        sa.Column(
            "expires_at",
            sa.DateTime(
                timezone=True
            ),
            nullable=False,
        ),
        sa.Column(
            "revoked_at",
            sa.DateTime(
                timezone=True
            ),
            nullable=True,
        ),
        sa.CheckConstraint(
            (
                "char_length("
                "btrim(refresh_token_hash)"
                ") = 64"
            ),
            name=(
                "ck_auth_session_"
                "refresh_token_hash_valid"
            ),
        ),
        sa.CheckConstraint(
            (
                "expires_at "
                "> created_at"
            ),
            name=(
                "ck_auth_session_"
                "expiration_order"
            ),
        ),
        sa.CheckConstraint(
            (
                "revoked_at IS NULL "
                "OR revoked_at >= created_at"
            ),
            name=(
                "ck_auth_session_"
                "revocation_order"
            ),
        ),
        sa.ForeignKeyConstraint(
            [
                "organization_id",
                "user_id",
            ],
            [
                (
                    f"{SCHEMA}."
                    "user_account."
                    "organization_id"
                ),
                (
                    f"{SCHEMA}."
                    "user_account.id"
                ),
            ],
            name=(
                "fk_auth_session_"
                "organization_user"
            ),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint(
            "id",
            name=(
                "pk_auth_session"
            ),
        ),
        sa.UniqueConstraint(
            "refresh_token_hash",
            name=(
                "uq_auth_session_"
                "refresh_token_hash"
            ),
        ),
        schema=SCHEMA,
    )

    op.create_index(
        (
            "ix_auth_session_"
            "organization_id"
        ),
        "auth_session",
        [
            "organization_id",
        ],
        unique=False,
        schema=SCHEMA,
    )

    op.create_index(
        "ix_auth_session_user_id",
        "auth_session",
        [
            "user_id",
        ],
        unique=False,
        schema=SCHEMA,
    )

    op.create_index(
        "ix_auth_session_expires_at",
        "auth_session",
        [
            "expires_at",
        ],
        unique=False,
        schema=SCHEMA,
    )