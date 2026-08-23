from __future__ import annotations

from typing import (
    Literal,
    cast,
)
from uuid import UUID

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
)
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
)

from application.ports.outbound.user_registration_repository import (
    UserRegistrationRepositoryError,
)
from application.services.user_registration_service import (
    InvalidRegistrationDataError,
    OrganizationSlugAlreadyExistsError,
    StaffEmailAlreadyExistsError,
    UserRegistrationService,
)
from domain.user_account import UserAccount
from infrastructure.api.auth_dependencies import (
    require_security_responsible_user,
)


UserRole = Literal[
    "staff",
    "security_responsible",
]


class RegistrationRequest(
    BaseModel
):
    model_config = ConfigDict(
        extra="forbid"
    )

    organization_name: str = Field(
        min_length=1,
        max_length=255,
    )

    organization_slug: str = Field(
        min_length=1,
        max_length=63,
    )

    display_name: str = Field(
        min_length=1,
        max_length=255,
    )

    email: str = Field(
        min_length=3,
        max_length=320,
    )

    password: str = Field(
        min_length=1,
        max_length=1024,
    )


class StaffAccountRequest(
    BaseModel
):
    model_config = ConfigDict(
        extra="forbid"
    )

    display_name: str = Field(
        min_length=1,
        max_length=255,
    )

    email: str = Field(
        min_length=3,
        max_length=320,
    )

    password: str = Field(
        min_length=1,
        max_length=1024,
    )


class RegisteredUserResponse(
    BaseModel
):
    user_id: UUID
    organization_id: UUID

    email: str
    display_name: str
    role: UserRole


class RegistrationResponse(
    BaseModel
):
    organization_id: UUID
    organization_name: str
    organization_slug: str
    user: RegisteredUserResponse


def _user_response(
    user: UserAccount,
) -> RegisteredUserResponse:
    return RegisteredUserResponse(
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


def create_registration_router(
    *,
    service: UserRegistrationService,
) -> APIRouter:
    if service is None:
        raise ValueError(
            "service must not be None"
        )

    router = APIRouter(
        prefix="/api/v1",
    )

    @router.post(
        "/auth/register",
        response_model=(
            RegistrationResponse
        ),
        status_code=(
            status.HTTP_201_CREATED
        ),
        tags=[
            "authentication",
        ],
    )
    def register(
        payload: RegistrationRequest,
    ) -> RegistrationResponse:
        try:
            result = service.register(
                organization_name=(
                    payload.organization_name
                ),
                organization_slug=(
                    payload.organization_slug
                ),
                display_name=(
                    payload.display_name
                ),
                email=payload.email,
                password=payload.password,
            )

        except (
            OrganizationSlugAlreadyExistsError
        ) as error:
            raise HTTPException(
                status_code=(
                    status.HTTP_409_CONFLICT
                ),
                detail=(
                    "Organization slug "
                    "already exists"
                ),
            ) from error

        except (
            InvalidRegistrationDataError
        ) as error:
            raise HTTPException(
                status_code=(
                    status
                    .HTTP_422_UNPROCESSABLE_ENTITY
                ),
                detail=str(error),
            ) from error

        except (
            UserRegistrationRepositoryError
        ) as error:
            raise HTTPException(
                status_code=(
                    status
                    .HTTP_503_SERVICE_UNAVAILABLE
                ),
                detail=(
                    "Registration service "
                    "is temporarily unavailable"
                ),
            ) from error

        return RegistrationResponse(
            organization_id=(
                result.organization.id
            ),
            organization_name=(
                result.organization.name
            ),
            organization_slug=(
                result.organization.slug
            ),
            user=_user_response(
                result.user
            ),
        )

    @router.post(
        "/users/staff",
        response_model=(
            RegisteredUserResponse
        ),
        status_code=(
            status.HTTP_201_CREATED
        ),
        tags=[
            "users",
        ],
    )
    def create_staff_account(
        payload: StaffAccountRequest,
        current_user: UserAccount = Depends(
            require_security_responsible_user
        ),
    ) -> RegisteredUserResponse:
        try:
            user = (
                service.create_staff_account(
                    organization_id=(
                        current_user.organization_id
                    ),
                    display_name=(
                        payload.display_name
                    ),
                    email=payload.email,
                    password=payload.password,
                )
            )

        except (
            StaffEmailAlreadyExistsError
        ) as error:
            raise HTTPException(
                status_code=(
                    status.HTTP_409_CONFLICT
                ),
                detail=(
                    "Email already exists "
                    "in organization"
                ),
            ) from error

        except (
            InvalidRegistrationDataError
        ) as error:
            raise HTTPException(
                status_code=(
                    status
                    .HTTP_422_UNPROCESSABLE_ENTITY
                ),
                detail=str(error),
            ) from error

        except (
            UserRegistrationRepositoryError
        ) as error:
            raise HTTPException(
                status_code=(
                    status
                    .HTTP_503_SERVICE_UNAVAILABLE
                ),
                detail=(
                    "User provisioning service "
                    "is temporarily unavailable"
                ),
            ) from error

        return _user_response(
            user
        )

    return router