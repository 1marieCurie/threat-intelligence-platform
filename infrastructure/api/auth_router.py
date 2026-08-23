from __future__ import annotations

from collections.abc import Callable
from typing import (
    Literal,
    cast,
)
from uuid import UUID

from fastapi import (
    APIRouter,
    Cookie,
    Depends,
    HTTPException,
    Response,
    status,
)
from pydantic import (
    BaseModel,
    Field,
)

from application.ports.outbound.authentication_repository import (
    AuthenticationRepositoryError,
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
from infrastructure.api.auth_dependencies import (
    create_current_user_dependency,
    require_bearer_token,
)


REFRESH_COOKIE_NAME = (
    "tip_refresh_token"
)

REFRESH_COOKIE_PATH = (
    "/api/v1/auth"
)


UserRole = Literal[
    "staff",
    "security_responsible",
]


class LoginRequest(
    BaseModel
):
    organization_slug: str = Field(
        min_length=1,
        max_length=63,
    )

    email: str = Field(
        min_length=3,
        max_length=320,
    )

    password: str = Field(
        min_length=1,
        max_length=1024,
    )


class UserResponse(
    BaseModel
):
    user_id: UUID
    organization_id: UUID

    email: str
    display_name: str

    role: UserRole


class TokenResponse(
    BaseModel
):
    access_token: str

    token_type: Literal[
        "bearer"
    ]

    expires_in: int = Field(
        gt=0
    )

    user: UserResponse


def _user_response(
    user: UserAccount,
) -> UserResponse:
    return UserResponse(
        user_id=user.id,
        organization_id=(
            user.organization_id
        ),
        email=user.email,
        display_name=(
            user.display_name
        ),
        role=cast(
            UserRole,
            user.role,
        ),
    )


def _set_refresh_cookie(
    *,
    response: Response,
    refresh_token: str,
    max_age_seconds: int,
    secure: bool,
) -> None:
    response.set_cookie(
        key=REFRESH_COOKIE_NAME,
        value=refresh_token,
        max_age=max_age_seconds,
        httponly=True,
        secure=secure,
        samesite="lax",
        path=REFRESH_COOKIE_PATH,
    )


def _delete_refresh_cookie(
    *,
    response: Response,
    secure: bool,
) -> None:
    response.delete_cookie(
        key=REFRESH_COOKIE_NAME,
        path=REFRESH_COOKIE_PATH,
        httponly=True,
        secure=secure,
        samesite="lax",
    )


def create_auth_router(
    *,
    service: UserAuthenticationService,
    refresh_token_ttl_seconds: int,
    cookie_secure: bool = False,
) -> APIRouter:
    if service is None:
        raise ValueError(
            "service must not be None"
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

    current_user_dependency: (
        Callable[..., UserAccount]
    ) = (
        create_current_user_dependency(
            service=service
        )
    )

    router = APIRouter(
        prefix="/api/v1/auth",
        tags=[
            "authentication",
        ],
    )

    @router.post(
        "/login",
        response_model=(
            TokenResponse
        ),
        status_code=(
            status.HTTP_200_OK
        ),
    )
    def login(
        payload: LoginRequest,
        response: Response,
    ) -> TokenResponse:
        try:
            result = (
                service.login(
                    organization_slug=(
                        payload
                        .organization_slug
                    ),
                    email=(
                        payload.email
                    ),
                    password=(
                        payload.password
                    ),
                )
            )

        except (
            InvalidCredentialsError
        ) as error:
            raise HTTPException(
                status_code=(
                    status
                    .HTTP_401_UNAUTHORIZED
                ),
                detail=(
                    "Invalid email or "
                    "password"
                ),
                headers={
                    "WWW-Authenticate": (
                        "Bearer"
                    ),
                },
            ) from error

        except (
            AuthenticationRepositoryError
        ) as error:
            raise HTTPException(
                status_code=(
                    status
                    .HTTP_503_SERVICE_UNAVAILABLE
                ),
                detail=(
                    "Authentication service "
                    "is temporarily unavailable"
                ),
            ) from error

        _set_refresh_cookie(
            response=response,
            refresh_token=(
                result.refresh_token
            ),
            max_age_seconds=(
                refresh_token_ttl_seconds
            ),
            secure=cookie_secure,
        )

        return TokenResponse(
            access_token=(
                result.access_token
            ),
            token_type="bearer",
            expires_in=(
                result
                .access_token_expires_in
            ),
            user=_user_response(
                result.user
            ),
        )

    @router.post(
        "/refresh",
        response_model=(
            TokenResponse
        ),
        status_code=(
            status.HTTP_200_OK
        ),
    )
    def refresh(
        response: Response,
        refresh_token: (
            str | None
        ) = Cookie(
            default=None,
            alias=(
                REFRESH_COOKIE_NAME
            ),
        ),
    ) -> TokenResponse:
        if not refresh_token:
            raise HTTPException(
                status_code=(
                    status
                    .HTTP_401_UNAUTHORIZED
                ),
                detail=(
                    "Refresh token required"
                ),
            )

        try:
            result = (
                service.refresh(
                    refresh_token=(
                        refresh_token
                    )
                )
            )

        except (
            InvalidRefreshTokenError
        ) as error:
            _delete_refresh_cookie(
                response=response,
                secure=cookie_secure,
            )

            raise HTTPException(
                status_code=(
                    status
                    .HTTP_401_UNAUTHORIZED
                ),
                detail=(
                    "Invalid or expired "
                    "refresh token"
                ),
            ) from error

        except (
            AuthenticationRepositoryError
        ) as error:
            raise HTTPException(
                status_code=(
                    status
                    .HTTP_503_SERVICE_UNAVAILABLE
                ),
                detail=(
                    "Authentication service "
                    "is temporarily unavailable"
                ),
            ) from error

        _set_refresh_cookie(
            response=response,
            refresh_token=(
                result.refresh_token
            ),
            max_age_seconds=(
                refresh_token_ttl_seconds
            ),
            secure=cookie_secure,
        )

        return TokenResponse(
            access_token=(
                result.access_token
            ),
            token_type="bearer",
            expires_in=(
                result
                .access_token_expires_in
            ),
            user=_user_response(
                result.user
            ),
        )

    @router.get(
        "/me",
        response_model=(
            UserResponse
        ),
        status_code=(
            status.HTTP_200_OK
        ),
    )
    def me(
        user: UserAccount = Depends(
            current_user_dependency
        ),
    ) -> UserResponse:
        return _user_response(
            user
        )

    @router.post(
        "/logout",
        status_code=(
            status
            .HTTP_204_NO_CONTENT
        ),
    )
    def logout(
        response: Response,
        access_token: str = Depends(
            require_bearer_token
        ),
    ) -> Response:
        try:
            service.logout(
                access_token=(
                    access_token
                )
            )

        except (
            InvalidAccessTokenError
        ) as error:
            _delete_refresh_cookie(
                response=response,
                secure=cookie_secure,
            )

            raise HTTPException(
                status_code=(
                    status
                    .HTTP_401_UNAUTHORIZED
                ),
                detail=(
                    "Invalid or expired "
                    "access token"
                ),
                headers={
                    "WWW-Authenticate": (
                        "Bearer"
                    ),
                },
            ) from error

        except (
            AuthenticationRepositoryError
        ) as error:
            raise HTTPException(
                status_code=(
                    status
                    .HTTP_503_SERVICE_UNAVAILABLE
                ),
                detail=(
                    "Authentication service "
                    "is temporarily unavailable"
                ),
            ) from error

        _delete_refresh_cookie(
            response=response,
            secure=cookie_secure,
        )

        response.status_code = (
            status
            .HTTP_204_NO_CONTENT
        )

        return response

    return router