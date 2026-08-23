from __future__ import annotations

from dataclasses import replace
from datetime import (
    UTC,
    datetime,
    timedelta,
)
from types import TracebackType
from uuid import (
    UUID,
    uuid4,
)

import pytest

from application.models.authentication import (
    AuthenticationSession,
    UserAuthenticationRecord,
)
from application.security.access_token_codec import (
    AccessTokenCodec,
)
from application.security.password_hasher import (
    PasswordHasher,
)
from application.security.refresh_tokens import (
    RefreshTokenManager,
)
from application.services.user_authentication_service import (
    InvalidAccessTokenError,
    InvalidCredentialsError,
    InvalidRefreshTokenError,
    UserAuthenticationService,
)
from domain.user_account import (
    UserAccount,
)


NOW = datetime.now(
    UTC
)

ORGANIZATION_ID = uuid4()
ORGANIZATION_SLUG = "tip-local"
USER_ID = uuid4()

PASSWORD = (
    "CorrectPassword2026!"
)

JWT_SECRET = (
    "authentication-service-test-"
    "secret-0123456789abcdef0123456789"
)


class FakeAuthenticationRepository:
    def __init__(
        self,
        *,
        record: (
            UserAuthenticationRecord
            | None
        ),
        organization_slug: str = (
            ORGANIZATION_SLUG
        ),
        organization_active: bool = True,
    ) -> None:
        self.record = record
        self.organization_slug = (
            organization_slug
        )
        self.organization_active = (
            organization_active
        )

        self.sessions: dict[
            UUID,
            AuthenticationSession,
        ] = {}

    def find_user_for_login(
        self,
        *,
        organization_slug: str,
        email: str,
    ):
        if (
            self.record is None
            or not self.organization_active
        ):
            return None

        if (
            self.organization_slug
            != organization_slug
            or self.record.user.email
            != email
        ):
            return None

        return self.record

    def find_user_by_id(
        self,
        *,
        organization_id: UUID,
        user_id: UUID,
    ):
        if (
            self.record is None
            or not self.organization_active
        ):
            return None

        user = self.record.user

        if (
            user.organization_id
            != organization_id
            or user.id
            != user_id
        ):
            return None

        return user

    def update_password_hash(
        self,
        *,
        organization_id: UUID,
        user_id: UUID,
        password_hash: str,
    ) -> None:
        if self.record is None:
            return

        self.record = (
            UserAuthenticationRecord(
                user=self.record.user,
                password_hash=(
                    password_hash
                ),
            )
        )

    def add_session(
        self,
        session: AuthenticationSession,
    ) -> None:
        self.sessions[
            session.id
        ] = session

    def find_session_by_id(
        self,
        *,
        organization_id: UUID,
        user_id: UUID,
        session_id: UUID,
    ):
        session = self.sessions.get(
            session_id
        )

        if session is None:
            return None

        if (
            session.organization_id
            != organization_id
            or session.user_id
            != user_id
        ):
            return None

        return session

    def find_session_by_refresh_token_hash(
        self,
        *,
        refresh_token_hash: str,
    ):
        for session in (
            self.sessions.values()
        ):
            if (
                session.refresh_token_hash
                == refresh_token_hash
            ):
                return session

        return None

    def rotate_refresh_token(
        self,
        *,
        session_id: UUID,
        current_refresh_token_hash: str,
        new_refresh_token_hash: str,
        new_expires_at: datetime,
    ) -> bool:
        session = self.sessions.get(
            session_id
        )

        if (
            session is None
            or session.is_revoked
            or (
                session
                .refresh_token_hash
                != current_refresh_token_hash
            )
        ):
            return False

        self.sessions[
            session_id
        ] = replace(
            session,
            refresh_token_hash=(
                new_refresh_token_hash
            ),
            expires_at=(
                new_expires_at
            ),
        )

        return True

    def revoke_session(
        self,
        *,
        session_id: UUID,
        revoked_at: datetime,
    ) -> bool:
        session = self.sessions.get(
            session_id
        )

        if (
            session is None
            or session.is_revoked
        ):
            return False

        self.sessions[
            session_id
        ] = replace(
            session,
            revoked_at=revoked_at,
        )

        return True


class FakeAuthenticationUnitOfWork:
    def __init__(
        self,
        repository: (
            FakeAuthenticationRepository
        ),
    ) -> None:
        self._repository = repository
        self.commit_count = 0

    @property
    def authentication(
        self,
    ):
        return self._repository

    def __enter__(
        self,
    ):
        return self

    def __exit__(
        self,
        exc_type: (
            type[BaseException]
            | None
        ),
        exc_value: (
            BaseException
            | None
        ),
        traceback: (
            TracebackType
            | None
        ),
    ) -> None:
        return None

    def commit(
        self,
    ) -> None:
        self.commit_count += 1

    def rollback(
        self,
    ) -> None:
        return None


def _user(
    *,
    role: str = "staff",
    is_active: bool = True,
) -> UserAccount:
    return UserAccount(
        id=USER_ID,
        organization_id=(
            ORGANIZATION_ID
        ),
        email="staff@tip.local",
        display_name="Staff",
        role=role,
        is_active=is_active,
        created_at=NOW,
    )


def _build_service(
    *,
    user: (
        UserAccount | None
    ) = None,
    organization_active: bool = True,
):
    password_hasher = (
        PasswordHasher()
    )

    if user is None:
        record = None

    else:
        record = (
            UserAuthenticationRecord(
                user=user,
                password_hash=(
                    password_hasher
                    .hash_password(
                        PASSWORD
                    )
                ),
            )
        )

    repository = (
        FakeAuthenticationRepository(
            record=record,
            organization_active=(
                organization_active
            ),
        )
    )

    unit_of_work = (
        FakeAuthenticationUnitOfWork(
            repository
        )
    )

    codec = AccessTokenCodec(
        secret=JWT_SECRET,
        issuer=(
            "threat-intelligence-platform"
        ),
        audience=(
            "threat-intelligence-platform-web"
        ),
        ttl_seconds=3600,
    )

    service = (
        UserAuthenticationService(
            unit_of_work=(
                unit_of_work
            ),
            password_hasher=(
                password_hasher
            ),
            access_token_codec=codec,
            refresh_token_manager=(
                RefreshTokenManager()
            ),
            access_token_ttl_seconds=(
                3600
            ),
            refresh_token_ttl_seconds=(
                30 * 24 * 60 * 60
            ),
            clock=lambda: NOW,
        )
    )

    return (
        service,
        repository,
        unit_of_work,
        codec,
    )


def test_login_creates_session_and_tokens(
) -> None:
    (
        service,
        repository,
        unit_of_work,
        codec,
    ) = _build_service(
        user=_user()
    )

    result = service.login(
        organization_slug=(
            " TIP-LOCAL "
        ),
        email="STAFF@TIP.LOCAL",
        password=PASSWORD,
    )

    assert (
        result.user.id
        == USER_ID
    )

    assert (
        result.token_type
        == "bearer"
    )

    assert result.access_token
    assert result.refresh_token

    assert len(
        repository.sessions
    ) == 1

    assert (
        unit_of_work.commit_count
        == 1
    )

    principal = (
        codec.decode_access_token(
            result.access_token
        )
    )

    assert principal is not None

    assert (
        principal.user_id
        == USER_ID
    )

    assert (
        principal.organization_id
        == ORGANIZATION_ID
    )


def test_login_rejects_wrong_password(
) -> None:
    (
        service,
        repository,
        _,
        _,
    ) = _build_service(
        user=_user()
    )

    with pytest.raises(
        InvalidCredentialsError
    ):
        service.login(
            organization_slug=(
                ORGANIZATION_SLUG
            ),
            email="staff@tip.local",
            password="WrongPassword!",
        )

    assert (
        repository.sessions
        == {}
    )


def test_login_rejects_invalid_slug(
) -> None:
    (
        service,
        repository,
        _,
        _,
    ) = _build_service(
        user=_user()
    )

    with pytest.raises(
        InvalidCredentialsError
    ):
        service.login(
            organization_slug=(
                "invalid slug!"
            ),
            email="staff@tip.local",
            password=PASSWORD,
        )

    assert repository.sessions == {}


def test_login_rejects_inactive_user(
) -> None:
    (
        service,
        repository,
        _,
        _,
    ) = _build_service(
        user=_user(
            is_active=False
        )
    )

    with pytest.raises(
        InvalidCredentialsError
    ):
        service.login(
            organization_slug=(
                ORGANIZATION_SLUG
            ),
            email="staff@tip.local",
            password=PASSWORD,
        )

    assert repository.sessions == {}


def test_login_rejects_inactive_organization(
) -> None:
    (
        service,
        repository,
        _,
        _,
    ) = _build_service(
        user=_user(),
        organization_active=False,
    )

    with pytest.raises(
        InvalidCredentialsError
    ):
        service.login(
            organization_slug=(
                ORGANIZATION_SLUG
            ),
            email="staff@tip.local",
            password=PASSWORD,
        )

    assert repository.sessions == {}


def test_refresh_rotates_refresh_token(
) -> None:
    (
        service,
        repository,
        unit_of_work,
        _,
    ) = _build_service(
        user=_user()
    )

    login_result = (
        service.login(
            organization_slug=(
                ORGANIZATION_SLUG
            ),
            email="staff@tip.local",
            password=PASSWORD,
        )
    )

    first_refresh_token = (
        login_result.refresh_token
    )

    refreshed = service.refresh(
        refresh_token=(
            first_refresh_token
        )
    )

    assert (
        refreshed.refresh_token
        != first_refresh_token
    )

    assert (
        unit_of_work.commit_count
        == 2
    )

    old_hash = (
        RefreshTokenManager
        .hash_token(
            first_refresh_token
        )
    )

    assert (
        repository
        .find_session_by_refresh_token_hash(
            refresh_token_hash=(
                old_hash
            )
        )
        is None
    )


def test_refresh_rejects_unknown_token(
) -> None:
    (
        service,
        _,
        _,
        _,
    ) = _build_service(
        user=_user()
    )

    with pytest.raises(
        InvalidRefreshTokenError
    ):
        service.refresh(
            refresh_token=(
                "unknown-refresh-token"
            )
        )


def test_refresh_rejects_deactivated_organization(
) -> None:
    (
        service,
        repository,
        _,
        _,
    ) = _build_service(
        user=_user()
    )

    login_result = service.login(
        organization_slug=(
            ORGANIZATION_SLUG
        ),
        email="staff@tip.local",
        password=PASSWORD,
    )

    repository.organization_active = False

    with pytest.raises(
        InvalidRefreshTokenError
    ):
        service.refresh(
            refresh_token=(
                login_result.refresh_token
            )
        )


def test_authenticate_access_token_returns_user(
) -> None:
    (
        service,
        _,
        _,
        _,
    ) = _build_service(
        user=_user()
    )

    login_result = (
        service.login(
            organization_slug=(
                ORGANIZATION_SLUG
            ),
            email="staff@tip.local",
            password=PASSWORD,
        )
    )

    user = (
        service
        .authenticate_access_token(
            access_token=(
                login_result
                .access_token
            )
        )
    )

    assert (
        user.id
        == USER_ID
    )

    assert (
        user.organization_id
        == ORGANIZATION_ID
    )


def test_access_token_rejects_deactivated_organization(
) -> None:
    (
        service,
        repository,
        _,
        _,
    ) = _build_service(
        user=_user()
    )

    login_result = service.login(
        organization_slug=(
            ORGANIZATION_SLUG
        ),
        email="staff@tip.local",
        password=PASSWORD,
    )

    repository.organization_active = False

    with pytest.raises(
        InvalidAccessTokenError
    ):
        service.authenticate_access_token(
            access_token=(
                login_result.access_token
            )
        )


def test_logout_revokes_session(
) -> None:
    (
        service,
        _,
        _,
        _,
    ) = _build_service(
        user=_user()
    )

    login_result = (
        service.login(
            organization_slug=(
                ORGANIZATION_SLUG
            ),
            email="staff@tip.local",
            password=PASSWORD,
        )
    )

    assert (
        service.logout(
            access_token=(
                login_result
                .access_token
            )
        )
        is True
    )

    with pytest.raises(
        InvalidAccessTokenError
    ):
        (
            service
            .authenticate_access_token(
                access_token=(
                    login_result
                    .access_token
                )
            )
        )


def test_access_token_role_change_is_rejected(
) -> None:
    (
        service,
        repository,
        _,
        _,
    ) = _build_service(
        user=_user(
            role="staff"
        )
    )

    login_result = (
        service.login(
            organization_slug=(
                ORGANIZATION_SLUG
            ),
            email="staff@tip.local",
            password=PASSWORD,
        )
    )

    assert (
        repository.record
        is not None
    )

    repository.record = (
        UserAuthenticationRecord(
            user=replace(
                repository
                .record
                .user,
                role=(
                    "security_responsible"
                ),
            ),
            password_hash=(
                repository
                .record
                .password_hash
            ),
        )
    )

    with pytest.raises(
        InvalidAccessTokenError
    ):
        (
            service
            .authenticate_access_token(
                access_token=(
                    login_result
                    .access_token
                )
            )
        )


def test_expired_session_rejects_access_token(
) -> None:
    (
        service,
        repository,
        _,
        codec,
    ) = _build_service(
        user=_user()
    )

    session_id = uuid4()

    repository.sessions[
        session_id
    ] = AuthenticationSession(
        id=session_id,
        organization_id=(
            ORGANIZATION_ID
        ),
        user_id=USER_ID,
        refresh_token_hash=(
            "a" * 64
        ),
        created_at=(
            NOW
            - timedelta(
                hours=2
            )
        ),
        expires_at=(
            NOW
            - timedelta(
                hours=1
            )
        ),
    )

    access_token = (
        codec.issue_access_token(
            user_id=USER_ID,
            organization_id=(
                ORGANIZATION_ID
            ),
            session_id=session_id,
            role="staff",
        )
    )

    with pytest.raises(
        InvalidAccessTokenError
    ):
        (
            service
            .authenticate_access_token(
                access_token=(
                    access_token
                )
            )
        )