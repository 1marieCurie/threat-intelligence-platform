from __future__ import annotations

from collections.abc import Callable
from datetime import (
    UTC,
    datetime,
    timedelta,
)
from uuid import (
    UUID,
    uuid4,
)

from application.models.authentication import (
    AuthenticationSession,
    AuthenticationTokenPair,
)
from application.ports.outbound.authentication_unit_of_work import (
    AuthenticationUnitOfWork,
)
from application.security.access_token_codec import (
    AccessTokenCodec,
    AccessTokenPrincipal,
)
from application.security.password_hasher import (
    PasswordHasher,
)
from application.security.refresh_tokens import (
    RefreshTokenManager,
)
from domain.user_account import (
    UserAccount,
)


class UserAuthenticationError(
    RuntimeError
):
    pass


class InvalidCredentialsError(
    UserAuthenticationError
):
    pass


class InvalidRefreshTokenError(
    UserAuthenticationError
):
    pass


class InvalidAccessTokenError(
    UserAuthenticationError
):
    pass


def _utc_now() -> datetime:
    return datetime.now(
        UTC
    )


class UserAuthenticationService:
    def __init__(
        self,
        *,
        unit_of_work: (
            AuthenticationUnitOfWork
        ),
        password_hasher: PasswordHasher,
        access_token_codec: (
            AccessTokenCodec
        ),
        refresh_token_manager: (
            RefreshTokenManager
        ),
        access_token_ttl_seconds: int,
        refresh_token_ttl_seconds: int,
        clock: Callable[
            [],
            datetime,
        ] = _utc_now,
        id_factory: Callable[
            [],
            UUID,
        ] = uuid4,
    ) -> None:
        if unit_of_work is None:
            raise ValueError(
                "unit_of_work must not be None"
            )

        if password_hasher is None:
            raise ValueError(
                "password_hasher must not be None"
            )

        if access_token_codec is None:
            raise ValueError(
                "access_token_codec "
                "must not be None"
            )

        if refresh_token_manager is None:
            raise ValueError(
                "refresh_token_manager "
                "must not be None"
            )

        if (
            not isinstance(
                access_token_ttl_seconds,
                int,
            )
            or access_token_ttl_seconds
            <= 0
        ):
            raise ValueError(
                "access_token_ttl_seconds "
                "must be positive"
            )

        if (
            not isinstance(
                refresh_token_ttl_seconds,
                int,
            )
            or refresh_token_ttl_seconds
            <= 0
        ):
            raise ValueError(
                "refresh_token_ttl_seconds "
                "must be positive"
            )

        if clock is None:
            raise ValueError(
                "clock must not be None"
            )

        if id_factory is None:
            raise ValueError(
                "id_factory must not be None"
            )

        self._unit_of_work = (
            unit_of_work
        )

        self._password_hasher = (
            password_hasher
        )

        self._access_token_codec = (
            access_token_codec
        )

        self._refresh_token_manager = (
            refresh_token_manager
        )

        self._access_token_ttl_seconds = (
            access_token_ttl_seconds
        )

        self._refresh_token_ttl_seconds = (
            refresh_token_ttl_seconds
        )

        self._clock = clock
        self._id_factory = id_factory

    def login(
        self,
        *,
        organization_id: UUID,
        email: str,
        password: str,
    ) -> AuthenticationTokenPair:
        if not isinstance(
            organization_id,
            UUID,
        ):
            raise TypeError(
                "organization_id must be UUID"
            )

        normalized_email = (
            self._normalize_email(
                email
            )
        )

        if (
            not isinstance(
                password,
                str,
            )
            or not password
        ):
            raise InvalidCredentialsError(
                "Invalid email or password"
            )

        now = self._now()

        with (
            self._unit_of_work
            as unit_of_work
        ):
            repository = (
                unit_of_work.authentication
            )

            authentication_record = (
                repository
                .find_user_for_login(
                    organization_id=(
                        organization_id
                    ),
                    email=(
                        normalized_email
                    ),
                )
            )

            if (
                authentication_record
                is None
            ):
                raise InvalidCredentialsError(
                    "Invalid email or password"
                )

            user = (
                authentication_record.user
            )

            if not user.is_active:
                raise InvalidCredentialsError(
                    "Invalid email or password"
                )

            valid_password = (
                self._password_hasher
                .verify_password(
                    password=password,
                    password_hash=(
                        authentication_record
                        .password_hash
                    ),
                )
            )

            if not valid_password:
                raise InvalidCredentialsError(
                    "Invalid email or password"
                )

            if (
                self._password_hasher
                .needs_rehash(
                    authentication_record
                    .password_hash
                )
            ):
                new_password_hash = (
                    self._password_hasher
                    .hash_password(
                        password
                    )
                )

                repository.update_password_hash(
                    organization_id=(
                        organization_id
                    ),
                    user_id=user.id,
                    password_hash=(
                        new_password_hash
                    ),
                )

            session_id = (
                self._id_factory()
            )

            refresh_token = (
                self._refresh_token_manager
                .issue()
            )

            authentication_session = (
                AuthenticationSession(
                    id=session_id,
                    organization_id=(
                        user.organization_id
                    ),
                    user_id=user.id,
                    refresh_token_hash=(
                        refresh_token.sha256
                    ),
                    created_at=now,
                    expires_at=(
                        now
                        + timedelta(
                            seconds=(
                                self
                                ._refresh_token_ttl_seconds
                            )
                        )
                    ),
                )
            )

            repository.add_session(
                authentication_session
            )

            access_token = (
                self._access_token_codec
                .issue_access_token(
                    user_id=user.id,
                    organization_id=(
                        user.organization_id
                    ),
                    session_id=(
                        session_id
                    ),
                    role=user.role,
                    issued_at=now,
                )
            )

            unit_of_work.commit()

            return AuthenticationTokenPair(
                access_token=(
                    access_token
                ),
                refresh_token=(
                    refresh_token.value
                ),
                access_token_expires_in=(
                    self
                    ._access_token_ttl_seconds
                ),
                token_type="bearer",
                user=user,
            )

    def refresh(
        self,
        *,
        refresh_token: str,
    ) -> AuthenticationTokenPair:
        if (
            not isinstance(
                refresh_token,
                str,
            )
            or not refresh_token.strip()
        ):
            raise InvalidRefreshTokenError(
                "Invalid refresh token"
            )

        refresh_token = (
            refresh_token.strip()
        )

        current_hash = (
            self._refresh_token_manager
            .hash_token(
                refresh_token
            )
        )

        now = self._now()

        with (
            self._unit_of_work
            as unit_of_work
        ):
            repository = (
                unit_of_work.authentication
            )

            authentication_session = (
                repository
                .find_session_by_refresh_token_hash(
                    refresh_token_hash=(
                        current_hash
                    )
                )
            )

            if (
                authentication_session
                is None
                or not (
                    authentication_session
                    .is_active(
                        now=now
                    )
                )
            ):
                raise InvalidRefreshTokenError(
                    "Invalid refresh token"
                )

            user = (
                repository.find_user_by_id(
                    organization_id=(
                        authentication_session
                        .organization_id
                    ),
                    user_id=(
                        authentication_session
                        .user_id
                    ),
                )
            )

            if (
                user is None
                or not user.is_active
            ):
                raise InvalidRefreshTokenError(
                    "Invalid refresh token"
                )

            new_refresh_token = (
                self._refresh_token_manager
                .issue()
            )

            rotated = (
                repository
                .rotate_refresh_token(
                    session_id=(
                        authentication_session.id
                    ),
                    current_refresh_token_hash=(
                        current_hash
                    ),
                    new_refresh_token_hash=(
                        new_refresh_token.sha256
                    ),
                    new_expires_at=(
                        now
                        + timedelta(
                            seconds=(
                                self
                                ._refresh_token_ttl_seconds
                            )
                        )
                    ),
                )
            )

            if not rotated:
                raise InvalidRefreshTokenError(
                    "Invalid refresh token"
                )

            access_token = (
                self._access_token_codec
                .issue_access_token(
                    user_id=user.id,
                    organization_id=(
                        user.organization_id
                    ),
                    session_id=(
                        authentication_session.id
                    ),
                    role=user.role,
                    issued_at=now,
                )
            )

            unit_of_work.commit()

            return AuthenticationTokenPair(
                access_token=(
                    access_token
                ),
                refresh_token=(
                    new_refresh_token.value
                ),
                access_token_expires_in=(
                    self
                    ._access_token_ttl_seconds
                ),
                token_type="bearer",
                user=user,
            )

    def authenticate_access_token(
        self,
        *,
        access_token: str,
    ) -> UserAccount:
        principal = (
            self._decode_access_token(
                access_token
            )
        )

        return (
            self._load_authenticated_user(
                principal=principal
            )
        )

    def logout(
        self,
        *,
        access_token: str,
    ) -> bool:
        principal = (
            self._decode_access_token(
                access_token
            )
        )

        now = self._now()

        with (
            self._unit_of_work
            as unit_of_work
        ):
            repository = (
                unit_of_work.authentication
            )

            authentication_session = (
                repository.find_session_by_id(
                    organization_id=(
                        principal
                        .organization_id
                    ),
                    user_id=(
                        principal.user_id
                    ),
                    session_id=(
                        principal.session_id
                    ),
                )
            )

            if (
                authentication_session
                is None
            ):
                return False

            if (
                authentication_session
                .is_revoked
            ):
                return False

            revoked = (
                repository.revoke_session(
                    session_id=(
                        principal.session_id
                    ),
                    revoked_at=now,
                )
            )

            if revoked:
                unit_of_work.commit()

            return revoked

    def _load_authenticated_user(
        self,
        *,
        principal: (
            AccessTokenPrincipal
        ),
    ) -> UserAccount:
        now = self._now()

        with (
            self._unit_of_work
            as unit_of_work
        ):
            repository = (
                unit_of_work.authentication
            )

            authentication_session = (
                repository.find_session_by_id(
                    organization_id=(
                        principal
                        .organization_id
                    ),
                    user_id=(
                        principal.user_id
                    ),
                    session_id=(
                        principal.session_id
                    ),
                )
            )

            if (
                authentication_session
                is None
                or not (
                    authentication_session
                    .is_active(
                        now=now
                    )
                )
            ):
                raise InvalidAccessTokenError(
                    "Invalid access token"
                )

            user = (
                repository.find_user_by_id(
                    organization_id=(
                        principal
                        .organization_id
                    ),
                    user_id=(
                        principal.user_id
                    ),
                )
            )

            if (
                user is None
                or not user.is_active
                or user.role
                != principal.role
            ):
                raise InvalidAccessTokenError(
                    "Invalid access token"
                )

            return user

    def _decode_access_token(
        self,
        access_token: str,
    ) -> AccessTokenPrincipal:
        principal = (
            self._access_token_codec
            .decode_access_token(
                access_token
            )
        )

        if principal is None:
            raise InvalidAccessTokenError(
                "Invalid access token"
            )

        return principal

    @staticmethod
    def _normalize_email(
        email: str,
    ) -> str:
        if not isinstance(
            email,
            str,
        ):
            raise InvalidCredentialsError(
                "Invalid email or password"
            )

        normalized = (
            email.strip().lower()
        )

        if (
            not normalized
            or "@" not in normalized
        ):
            raise InvalidCredentialsError(
                "Invalid email or password"
            )

        return normalized

    def _now(
        self,
    ) -> datetime:
        now = self._clock()

        if not isinstance(
            now,
            datetime,
        ):
            raise TypeError(
                "clock must return datetime"
            )

        if (
            now.tzinfo is None
            or now.utcoffset()
            is None
        ):
            raise ValueError(
                "clock must return "
                "timezone-aware datetime"
            )

        return now.astimezone(
            UTC
        )