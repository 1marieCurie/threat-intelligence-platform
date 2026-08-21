from __future__ import annotations

from datetime import datetime
from typing import Protocol
from uuid import UUID

from application.models.authentication import (
    AuthenticationSession,
    UserAuthenticationRecord,
)
from domain.user_account import (
    UserAccount,
)


class AuthenticationRepositoryError(
    RuntimeError
):
    pass


class AuthenticationConflictError(
    AuthenticationRepositoryError
):
    pass


class AuthenticationRepository(
    Protocol
):
    def find_user_for_login(
        self,
        *,
        organization_id: UUID,
        email: str,
    ) -> (
        UserAuthenticationRecord
        | None
    ):
        ...

    def find_user_by_id(
        self,
        *,
        organization_id: UUID,
        user_id: UUID,
    ) -> UserAccount | None:
        ...

    def update_password_hash(
        self,
        *,
        organization_id: UUID,
        user_id: UUID,
        password_hash: str,
    ) -> None:
        ...

    def add_session(
        self,
        session: AuthenticationSession,
    ) -> None:
        ...

    def find_session_by_id(
        self,
        *,
        organization_id: UUID,
        user_id: UUID,
        session_id: UUID,
    ) -> (
        AuthenticationSession
        | None
    ):
        ...

    def find_session_by_refresh_token_hash(
        self,
        *,
        refresh_token_hash: str,
    ) -> (
        AuthenticationSession
        | None
    ):
        ...

    def rotate_refresh_token(
        self,
        *,
        session_id: UUID,
        current_refresh_token_hash: str,
        new_refresh_token_hash: str,
        new_expires_at: datetime,
    ) -> bool:
        ...

    def revoke_session(
        self,
        *,
        session_id: UUID,
        revoked_at: datetime,
    ) -> bool:
        ...