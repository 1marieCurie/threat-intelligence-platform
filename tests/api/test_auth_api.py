from __future__ import annotations

from datetime import (
    UTC,
    datetime,
)
from unittest.mock import Mock
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import (
    TestClient,
)

from application.models.authentication import (
    AuthenticationTokenPair,
)
from application.services.user_authentication_service import (
    InvalidCredentialsError,
    InvalidRefreshTokenError,
    UserAuthenticationService,
)
from domain.user_account import (
    UserAccount,
)
from infrastructure.api.auth_router import (
    REFRESH_COOKIE_NAME,
    REFRESH_COOKIE_PATH,
    create_auth_router,
)


ORGANIZATION_ID = uuid4()
USER_ID = uuid4()

NOW = datetime(
    2026,
    8,
    21,
    18,
    0,
    tzinfo=UTC,
)


def _user(
    *,
    role: str = "staff",
) -> UserAccount:
    return UserAccount(
        id=USER_ID,
        organization_id=(
            ORGANIZATION_ID
        ),
        email=(
            "staff@tip.local"
        ),
        display_name=(
            "Development Staff"
        ),
        role=role,
        is_active=True,
        created_at=NOW,
    )


def _token_pair(
    *,
    access_token: str = (
        "access-token"
    ),
    refresh_token: str = (
        "refresh-token"
    ),
) -> AuthenticationTokenPair:
    return AuthenticationTokenPair(
        access_token=(
            access_token
        ),
        refresh_token=(
            refresh_token
        ),
        access_token_expires_in=900,
        token_type="bearer",
        user=_user(),
    )


def _client(
    service: UserAuthenticationService,
) -> TestClient:
    app = FastAPI()

    app.include_router(
        create_auth_router(
            service=service,
            refresh_token_ttl_seconds=(
                30
                * 24
                * 60
                * 60
            ),
            cookie_secure=False,
        )
    )

    return TestClient(
        app
    )


def test_login_returns_access_token_and_sets_refresh_cookie(
) -> None:
    service = Mock(
        spec=(
            UserAuthenticationService
        )
    )

    service.login.return_value = (
        _token_pair()
    )

    client = _client(
        service
    )

    response = client.post(
        "/api/v1/auth/login",
        json={
            "organization_id": str(
                ORGANIZATION_ID
            ),
            "email": (
                "staff@tip.local"
            ),
            "password": (
                "StaffDev2026!"
            ),
        },
    )

    assert (
        response.status_code
        == 200
    )

    body = response.json()

    assert (
        body["access_token"]
        == "access-token"
    )

    assert (
        body["token_type"]
        == "bearer"
    )

    assert (
        body["expires_in"]
        == 900
    )

    assert (
        body["user"]
        == {
            "user_id": str(
                USER_ID
            ),
            "organization_id": str(
                ORGANIZATION_ID
            ),
            "email": (
                "staff@tip.local"
            ),
            "display_name": (
                "Development Staff"
            ),
            "role": "staff",
        }
    )

    assert (
        client.cookies.get(
            REFRESH_COOKIE_NAME,
            domain=(
                "testserver.local"
            ),
            path=(
                REFRESH_COOKIE_PATH
            ),
        )
        == "refresh-token"
    )

    set_cookie = (
        response.headers[
            "set-cookie"
        ]
    )

    assert (
        "HttpOnly"
        in set_cookie
    )

    service.login.assert_called_once_with(
        organization_id=(
            ORGANIZATION_ID
        ),
        email=(
            "staff@tip.local"
        ),
        password=(
            "StaffDev2026!"
        ),
    )


def test_login_rejects_invalid_credentials(
) -> None:
    service = Mock(
        spec=(
            UserAuthenticationService
        )
    )

    service.login.side_effect = (
        InvalidCredentialsError(
            "invalid"
        )
    )

    client = _client(
        service
    )

    response = client.post(
        "/api/v1/auth/login",
        json={
            "organization_id": str(
                ORGANIZATION_ID
            ),
            "email": (
                "staff@tip.local"
            ),
            "password": "wrong",
        },
    )

    assert (
        response.status_code
        == 401
    )

    assert (
        response.json()
        == {
            "detail": (
                "Invalid email or "
                "password"
            )
        }
    )


def test_refresh_rotates_cookie(
) -> None:
    service = Mock(
        spec=(
            UserAuthenticationService
        )
    )

    service.refresh.return_value = (
        _token_pair(
            access_token=(
                "new-access-token"
            ),
            refresh_token=(
                "new-refresh-token"
            ),
        )
    )

    client = _client(
        service
    )

    response = client.post(
        "/api/v1/auth/refresh",
        headers={
            "Cookie": (
                f"{REFRESH_COOKIE_NAME}="
                "old-refresh-token"
            ),
        },
    )

    assert (
        response.status_code
        == 200
    )

    assert (
        response.json()[
            "access_token"
        ]
        == "new-access-token"
    )

    assert (
        client.cookies.get(
            REFRESH_COOKIE_NAME,
            domain=(
                "testserver.local"
            ),
            path=(
                REFRESH_COOKIE_PATH
            ),
        )
        == "new-refresh-token"
    )

    service.refresh.assert_called_once_with(
        refresh_token=(
            "old-refresh-token"
        )
    )


def test_refresh_rejects_invalid_token(
) -> None:
    service = Mock(
        spec=(
            UserAuthenticationService
        )
    )

    service.refresh.side_effect = (
        InvalidRefreshTokenError(
            "invalid"
        )
    )

    client = _client(
        service
    )

    response = client.post(
        "/api/v1/auth/refresh",
        headers={
            "Cookie": (
                f"{REFRESH_COOKIE_NAME}="
                "bad-token"
            ),
        },
    )

    assert (
        response.status_code
        == 401
    )

    assert (
        response.json()
        == {
            "detail": (
                "Invalid or expired "
                "refresh token"
            )
        }
    )


def test_me_returns_authenticated_user(
) -> None:
    service = Mock(
        spec=(
            UserAuthenticationService
        )
    )

    service.authenticate_access_token.return_value = (
        _user()
    )

    client = _client(
        service
    )

    response = client.get(
        "/api/v1/auth/me",
        headers={
            "Authorization": (
                "Bearer valid-token"
            ),
        },
    )

    assert (
        response.status_code
        == 200
    )

    assert (
        response.json()["role"]
        == "staff"
    )

    (
        service
        .authenticate_access_token
        .assert_called_once_with(
            access_token=(
                "valid-token"
            )
        )
    )


def test_me_requires_bearer_token(
) -> None:
    service = Mock(
        spec=(
            UserAuthenticationService
        )
    )

    client = _client(
        service
    )

    response = client.get(
        "/api/v1/auth/me"
    )

    assert (
        response.status_code
        == 401
    )

    (
        service
        .authenticate_access_token
        .assert_not_called()
    )


def test_logout_revokes_session_and_clears_cookie(
) -> None:
    service = Mock(
        spec=(
            UserAuthenticationService
        )
    )

    service.logout.return_value = (
        True
    )

    client = _client(
        service
    )

    response = client.post(
        "/api/v1/auth/logout",
        headers={
            "Authorization": (
                "Bearer access-token"
            ),
            "Cookie": (
                f"{REFRESH_COOKIE_NAME}="
                "refresh-token"
            ),
        },
    )

    assert (
        response.status_code
        == 204
    )

    service.logout.assert_called_once_with(
        access_token=(
            "access-token"
        )
    )

    set_cookie = (
        response.headers[
            "set-cookie"
        ]
    )

    assert (
        REFRESH_COOKIE_NAME
        in set_cookie
    )

    assert (
        "Max-Age=0"
        in set_cookie
        or "max-age=0"
        in set_cookie.lower()
    )