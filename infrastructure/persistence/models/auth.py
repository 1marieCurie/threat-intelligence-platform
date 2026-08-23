from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    String,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
)

from infrastructure.persistence.models.base import (
    Base,
)


SCHEMA = "threat_intel"


class AuthSessionModel(Base):
    __tablename__ = "auth_session"

    __table_args__ = (
        CheckConstraint(
            (
                "char_length("
                "btrim(refresh_token_hash)"
                ") = 64"
            ),
            name="refresh_token_hash_valid",
        ),
        CheckConstraint(
            "expires_at > created_at",
            name="expiration_order",
        ),
        CheckConstraint(
            (
                "revoked_at IS NULL "
                "OR revoked_at >= created_at"
            ),
            name="revocation_order",
        ),
        ForeignKeyConstraint(
            [
                "organization_id",
                "user_id",
            ],
            [
                (
                    f"{SCHEMA}."
                    "user_account.organization_id"
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
        UniqueConstraint(
            "refresh_token_hash",
            name=(
                "uq_auth_session_"
                "refresh_token_hash"
            ),
        ),
        Index(
            (
                "ix_auth_session_"
                "organization_id"
            ),
            "organization_id",
        ),
        Index(
            "ix_auth_session_user_id",
            "user_id",
        ),
        Index(
            "ix_auth_session_expires_at",
            "expires_at",
        ),
        {
            "schema": SCHEMA,
        },
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    organization_id: Mapped[
        uuid.UUID
    ] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
    )

    user_id: Mapped[
        uuid.UUID
    ] = mapped_column(
        UUID(as_uuid=True),
        nullable=False,
    )

    refresh_token_hash: Mapped[
        str
    ] = mapped_column(
        String(64),
        nullable=False,
    )

    created_at: Mapped[
        datetime
    ] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    expires_at: Mapped[
        datetime
    ] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
    )

    revoked_at: Mapped[
        datetime | None
    ] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
    )