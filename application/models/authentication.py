from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from domain.user_account import (
    UserAccount,
)


@dataclass(
    frozen=True,
    slots=True,
)
class UserAuthenticationRecord:
    user: UserAccount
    password_hash: str

    def __post_init__(
        self,
    ) -> None:
        if not isinstance(
            self.user,
            UserAccount,
        ):
            raise TypeError(
                "user must be UserAccount"
            )

        if not isinstance(
            self.password_hash,
            str,
        ):
            raise TypeError(
                "password_hash must be string"
            )

        if not self.password_hash.strip():
            raise ValueError(
                "password_hash must not be empty"
            )


@dataclass(
    frozen=True,
    slots=True,
)
class AuthenticationSession:
    id: UUID
    organization_id: UUID
    user_id: UUID
    refresh_token_hash: str
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None

    @property
    def is_revoked(
        self,
    ) -> bool:
        return (
            self.revoked_at
            is not None
        )

    def is_expired(
        self,
        *,
        now: datetime,
    ) -> bool:
        if (
            now.tzinfo is None
            or now.utcoffset()
            is None
        ):
            raise ValueError(
                "now must be timezone-aware"
            )

        return (
            now >= self.expires_at
        )

    def is_active(
        self,
        *,
        now: datetime,
    ) -> bool:
        return (
            not self.is_revoked
            and not self.is_expired(
                now=now
            )
        )


@dataclass(
    frozen=True,
    slots=True,
)
class AuthenticationTokenPair:
    access_token: str
    refresh_token: str
    access_token_expires_in: int
    token_type: str
    user: UserAccount