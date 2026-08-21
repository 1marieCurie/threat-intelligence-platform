from __future__ import annotations

from collections.abc import Callable
from uuid import UUID

from fastapi import (
    Depends,
    HTTPException,
    Request,
    status,
)
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
)

from application.ports.outbound.authentication_repository import (
    AuthenticationRepositoryError,
)
from application.services.user_authentication_service import (
    InvalidAccessTokenError,
    UserAuthenticationService,
)
from domain.user_account import (
    UserAccount,
)


_bearer_scheme = HTTPBearer(
    auto_error=False
)


def require_bearer_token(
    credentials: (
        HTTPAuthorizationCredentials
        | None
    ) = Depends(
        _bearer_scheme
    ),
) -> str:
    if (
        credentials is None
        or credentials.scheme.lower()
        != "bearer"
        or not credentials.credentials
    ):
        raise HTTPException(
            status_code=(
                status.HTTP_401_UNAUTHORIZED
            ),
            detail=(
                "Authentication required"
            ),
            headers={
                "WWW-Authenticate": (
                    "Bearer"
                ),
            },
        )

    return credentials.credentials


def _authenticate_user(
    *,
    service: UserAuthenticationService,
    access_token: str,
) -> UserAccount:
    try:
        return (
            service
            .authenticate_access_token(
                access_token=(
                    access_token
                )
            )
        )

    except InvalidAccessTokenError as error:
        raise HTTPException(
            status_code=(
                status.HTTP_401_UNAUTHORIZED
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

    except AuthenticationRepositoryError as error:
        raise HTTPException(
            status_code=(
                status
                .HTTP_503_SERVICE_UNAVAILABLE
            ),
            detail=(
                "Authentication service is "
                "temporarily unavailable"
            ),
        ) from error


def create_current_user_dependency(
    *,
    service: UserAuthenticationService,
) -> Callable[..., UserAccount]:
    if service is None:
        raise ValueError(
            "service must not be None"
        )

    def get_current_user(
        access_token: str = Depends(
            require_bearer_token
        ),
    ) -> UserAccount:
        return _authenticate_user(
            service=service,
            access_token=access_token,
        )

    return get_current_user


def create_security_responsible_dependency(
    *,
    current_user_dependency: (
        Callable[..., UserAccount]
    ),
) -> Callable[..., UserAccount]:
    if current_user_dependency is None:
        raise ValueError(
            "current_user_dependency "
            "must not be None"
        )

    def require_security_responsible(
        user: UserAccount = Depends(
            current_user_dependency
        ),
    ) -> UserAccount:
        if (
            user.role
            != "security_responsible"
        ):
            raise HTTPException(
                status_code=(
                    status.HTTP_403_FORBIDDEN
                ),
                detail=(
                    "Security responsible "
                    "role required"
                ),
            )

        return user

    return require_security_responsible


def require_authenticated_user(
    request: Request,
    access_token: str = Depends(
        require_bearer_token
    ),
) -> UserAccount:
    service = getattr(
        request.app.state,
        "user_authentication_service",
        None,
    )

    if service is None:
        raise HTTPException(
            status_code=(
                status
                .HTTP_503_SERVICE_UNAVAILABLE
            ),
            detail=(
                "Authentication service is "
                "not configured"
            ),
        )

    return _authenticate_user(
        service=service,
        access_token=access_token,
    )


def require_security_responsible_user(
    user: UserAccount = Depends(
        require_authenticated_user
    ),
) -> UserAccount:
    if (
        user.role
        != "security_responsible"
    ):
        raise HTTPException(
            status_code=(
                status.HTTP_403_FORBIDDEN
            ),
            detail=(
                "Security responsible "
                "role required"
            ),
        )

    return user


def require_security_organization_id(
    user: UserAccount = Depends(
        require_security_responsible_user
    ),
) -> UUID:
    return user.organization_id