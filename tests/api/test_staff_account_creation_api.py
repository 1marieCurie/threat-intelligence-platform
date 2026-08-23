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

from application.services.user_authentication_service import (
    UserAuthenticationService,
)
from application.services.user_registration_service import (
    StaffEmailAlreadyExistsError,
    UserRegistrationService,
)
from domain.user_account import UserAccount
from infrastructure.api.registration_router import (
    create_registration_router,
)


NOW = datetime(
    2026,
    8,
    23,
    15,
    0,
    tzinfo=UTC,
)


def _user(
    *,
    role: str,
) -> UserAccount:
    return UserAccount(
        id=uuid4(),
        organization_id=uuid4(),
        email=(
            "security@example.test"
            if role
            == "security_responsible"
            else "staff@example.test"
        ),
        display_name="Test User",
        role=role,
        is_active=True,
        created_at=NOW,
    )


def _client(
    *,
    authenticated_user: (
        UserAccount
        | None
    ),
) -> tuple[
    TestClient,
    Mock,
]:
    registration_service = Mock(
        spec=UserRegistrationService
    )

    authentication_service = Mock(
        spec=UserAuthenticationService
    )

    if (
        authenticated_user
        is not None
    ):
        (
            authentication_service
            .authenticate_access_token
            .return_value
        ) = authenticated_user

    app = FastAPI()

    app.state.user_authentication_service = (
        authentication_service
    )

    app.include_router(
        create_registration_router(
            service=(
                registration_service
            )
        )
    )

    return (
        TestClient(app),
        registration_service,
    )


def test_security_responsible_can_create_staff_account(
) -> None:
    security_user = _user(
        role=(
            "security_responsible"
        )
    )

    client, service = _client(
        authenticated_user=(
            security_user
        )
    )

    created_user = UserAccount(
        id=uuid4(),
        organization_id=(
            security_user.organization_id
        ),
        email=(
            "new.staff@example.test"
        ),
        display_name=(
            "New Staff"
        ),
        role="staff",
        is_active=True,
        created_at=NOW,
    )

    (
        service
        .create_staff_account
        .return_value
    ) = created_user

    response = client.post(
        "/api/v1/users/staff",
        headers={
            "Authorization": (
                "Bearer security-token"
            )
        },
        json={
            "display_name": (
                "New Staff"
            ),
            "email": (
                "new.staff@example.test"
            ),
            "password": (
                "staff-password"
            ),
        },
    )

    assert (
        response.status_code
        == 201
    )

    payload = response.json()

    assert (
        payload["organization_id"]
        == str(
            security_user
            .organization_id
        )
    )

    assert (
        payload["role"]
        == "staff"
    )

    (
        service
        .create_staff_account
        .assert_called_once_with(
            organization_id=(
                security_user
                .organization_id
            ),
            display_name=(
                "New Staff"
            ),
            email=(
                "new.staff@example.test"
            ),
            password=(
                "staff-password"
            ),
        )
    )


def test_staff_cannot_create_another_staff_account(
) -> None:
    client, service = _client(
        authenticated_user=_user(
            role="staff"
        )
    )

    response = client.post(
        "/api/v1/users/staff",
        headers={
            "Authorization": (
                "Bearer staff-token"
            )
        },
        json={
            "display_name": (
                "Another Staff"
            ),
            "email": (
                "another@example.test"
            ),
            "password": (
                "staff-password"
            ),
        },
    )

    assert (
        response.status_code
        == 403
    )

    (
        service
        .create_staff_account
        .assert_not_called()
    )


def test_staff_creation_requires_authentication(
) -> None:
    client, service = _client(
        authenticated_user=None
    )

    response = client.post(
        "/api/v1/users/staff",
        json={
            "display_name": (
                "Another Staff"
            ),
            "email": (
                "another@example.test"
            ),
            "password": (
                "staff-password"
            ),
        },
    )

    assert (
        response.status_code
        == 401
    )

    (
        service
        .create_staff_account
        .assert_not_called()
    )


def test_staff_creation_forbids_role_and_organization_id(
) -> None:
    security_user = _user(
        role=(
            "security_responsible"
        )
    )

    client, service = _client(
        authenticated_user=(
            security_user
        )
    )

    response = client.post(
        "/api/v1/users/staff",
        headers={
            "Authorization": (
                "Bearer security-token"
            )
        },
        json={
            "display_name": (
                "New Staff"
            ),
            "email": (
                "new.staff@example.test"
            ),
            "password": (
                "staff-password"
            ),
            "role": (
                "security_responsible"
            ),
            "organization_id": str(
                uuid4()
            ),
        },
    )

    assert (
        response.status_code
        == 422
    )

    (
        service
        .create_staff_account
        .assert_not_called()
    )


def test_existing_staff_email_returns_conflict(
) -> None:
    security_user = _user(
        role=(
            "security_responsible"
        )
    )

    client, service = _client(
        authenticated_user=(
            security_user
        )
    )

    (
        service
        .create_staff_account
        .side_effect
    ) = StaffEmailAlreadyExistsError(
        (
            "Email already exists "
            "in organization"
        )
    )

    response = client.post(
        "/api/v1/users/staff",
        headers={
            "Authorization": (
                "Bearer security-token"
            )
        },
        json={
            "display_name": (
                "Existing Staff"
            ),
            "email": (
                "existing@example.test"
            ),
            "password": (
                "staff-password"
            ),
        },
    )

    assert (
        response.status_code
        == 409
    )