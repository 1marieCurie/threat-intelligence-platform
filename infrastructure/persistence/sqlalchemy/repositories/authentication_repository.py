from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    select,
    update,
)
from sqlalchemy.exc import (
    SQLAlchemyError,
)
from sqlalchemy.orm import Session

from application.models.authentication import (
    AuthenticationSession,
    UserAuthenticationRecord,
)
from application.ports.outbound.authentication_repository import (
    AuthenticationRepositoryError,
)
from domain.user_account import (
    UserAccount,
)
from infrastructure.persistence.models.assets import (
    UserAccountModel,
)
from infrastructure.persistence.models.auth import (
    AuthSessionModel,
)


class SqlAlchemyAuthenticationRepository:
    def __init__(
        self,
        *,
        session: Session,
    ) -> None:
        if session is None:
            raise ValueError(
                "session must not be None"
            )

        self._session = session

    def find_user_for_login(
        self,
        *,
        organization_id: UUID,
        email: str,
    ) -> (
        UserAuthenticationRecord
        | None
    ):
        normalized_email = (
            email.strip().lower()
        )

        try:
            model = (
                self._session.scalar(
                    select(
                        UserAccountModel
                    ).where(
                        UserAccountModel.organization_id
                        == organization_id,
                        UserAccountModel.email
                        == normalized_email,
                    )
                )
            )

        except SQLAlchemyError as error:
            raise AuthenticationRepositoryError(
                "Unable to read user account"
            ) from error

        if model is None:
            return None

        return (
            UserAuthenticationRecord(
                user=(
                    self._to_user(
                        model
                    )
                ),
                password_hash=(
                    model.password_hash
                ),
            )
        )

    def find_user_by_id(
        self,
        *,
        organization_id: UUID,
        user_id: UUID,
    ) -> UserAccount | None:
        try:
            model = (
                self._session.scalar(
                    select(
                        UserAccountModel
                    ).where(
                        UserAccountModel.organization_id
                        == organization_id,
                        UserAccountModel.id
                        == user_id,
                    )
                )
            )

        except SQLAlchemyError as error:
            raise AuthenticationRepositoryError(
                "Unable to read user account"
            ) from error

        if model is None:
            return None

        return self._to_user(
            model
        )

    def update_password_hash(
        self,
        *,
        organization_id: UUID,
        user_id: UUID,
        password_hash: str,
    ) -> None:
        try:
            self._session.execute(
                update(
                    UserAccountModel
                )
                .where(
                    UserAccountModel.organization_id
                    == organization_id,
                    UserAccountModel.id
                    == user_id,
                )
                .values(
                    password_hash=(
                        password_hash
                    )
                )
            )

        except SQLAlchemyError as error:
            raise AuthenticationRepositoryError(
                "Unable to update "
                "password hash"
            ) from error

    def add_session(
        self,
        session: AuthenticationSession,
    ) -> None:
        try:
            self._session.add(
                AuthSessionModel(
                    id=session.id,
                    organization_id=(
                        session.organization_id
                    ),
                    user_id=(
                        session.user_id
                    ),
                    refresh_token_hash=(
                        session
                        .refresh_token_hash
                    ),
                    created_at=(
                        session.created_at
                    ),
                    expires_at=(
                        session.expires_at
                    ),
                    revoked_at=(
                        session.revoked_at
                    ),
                )
            )

        except SQLAlchemyError as error:
            raise AuthenticationRepositoryError(
                "Unable to add "
                "authentication session"
            ) from error

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
        try:
            model = (
                self._session.scalar(
                    select(
                        AuthSessionModel
                    ).where(
                        AuthSessionModel.organization_id
                        == organization_id,
                        AuthSessionModel.user_id
                        == user_id,
                        AuthSessionModel.id
                        == session_id,
                    )
                )
            )

        except SQLAlchemyError as error:
            raise AuthenticationRepositoryError(
                "Unable to read "
                "authentication session"
            ) from error

        if model is None:
            return None

        return self._to_session(
            model
        )

    def find_session_by_refresh_token_hash(
        self,
        *,
        refresh_token_hash: str,
    ) -> (
        AuthenticationSession
        | None
    ):
        try:
            model = (
                self._session.scalar(
                    select(
                        AuthSessionModel
                    ).where(
                        AuthSessionModel.refresh_token_hash
                        == refresh_token_hash
                    )
                )
            )

        except SQLAlchemyError as error:
            raise AuthenticationRepositoryError(
                "Unable to read "
                "refresh session"
            ) from error

        if model is None:
            return None

        return self._to_session(
            model
        )

    def rotate_refresh_token(
        self,
        *,
        session_id: UUID,
        current_refresh_token_hash: str,
        new_refresh_token_hash: str,
        new_expires_at: datetime,
    ) -> bool:
        try:
            result = (
                self._session.execute(
                    update(
                        AuthSessionModel
                    )
                    .where(
                        AuthSessionModel.id
                        == session_id,
                        AuthSessionModel.refresh_token_hash
                        == current_refresh_token_hash,
                        AuthSessionModel.revoked_at
                        .is_(None),
                    )
                    .values(
                        refresh_token_hash=(
                            new_refresh_token_hash
                        ),
                        expires_at=(
                            new_expires_at
                        ),
                    )
                )
            )

        except SQLAlchemyError as error:
            raise AuthenticationRepositoryError(
                "Unable to rotate "
                "refresh token"
            ) from error

        return (
            result.rowcount == 1 # pyright: ignore[reportAttributeAccessIssue]
        )

    def revoke_session(
        self,
        *,
        session_id: UUID,
        revoked_at: datetime,
    ) -> bool:
        try:
            result = (
                self._session.execute(
                    update(
                        AuthSessionModel
                    )
                    .where(
                        AuthSessionModel.id
                        == session_id,
                        AuthSessionModel.revoked_at
                        .is_(None),
                    )
                    .values(
                        revoked_at=(
                            revoked_at
                        )
                    )
                )
            )

        except SQLAlchemyError as error:
            raise AuthenticationRepositoryError(
                "Unable to revoke "
                "authentication session"
            ) from error

        return (
            result.rowcount == 1 # pyright: ignore[reportAttributeAccessIssue]
        )

    @staticmethod
    def _to_user(
        model: UserAccountModel,
    ) -> UserAccount:
        return UserAccount(
            id=model.id,
            organization_id=(
                model.organization_id
            ),
            email=model.email,
            display_name=(
                model.display_name
            ),
            role=model.role,
            is_active=(
                model.is_active
            ),
            created_at=(
                model.created_at
            ),
        )

    @staticmethod
    def _to_session(
        model: AuthSessionModel,
    ) -> AuthenticationSession:
        return AuthenticationSession(
            id=model.id,
            organization_id=(
                model.organization_id
            ),
            user_id=model.user_id,
            refresh_token_hash=(
                model.refresh_token_hash
            ),
            created_at=(
                model.created_at
            ),
            expires_at=(
                model.expires_at
            ),
            revoked_at=(
                model.revoked_at
            ),
        )