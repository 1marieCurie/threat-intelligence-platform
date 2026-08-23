from __future__ import annotations

from types import SimpleNamespace
from uuid import UUID

import pytest
from fastapi import FastAPI
from fastapi.testclient import (
    TestClient,
)

from application.services.user_registration_service import (
    OrganizationSlugAlreadyExistsError,
)
from infrastructure.api.registration_router import (
    create_registration_router,
)


ORGANIZATION_ID = UUID(
    "11111111-1111-4111-8111-111111111111"
)

USER_ID = UUID(
    "22222222-2222-4222-8222-222222222222"
)


class FakeRegistrationService:
    def __init__(
        self,
        *,
        conflict: bool = False,
    ) -> None:
        self.conflict = conflict
        self.calls = 0
        self.last_payload: (
            dict[str, str] | None
        ) = None

    def register(
        self,
        *,
        organization_name: str,
        organization_slug: str,
        display_name: str,
        email: str,
        password: str,
    ):
        self.calls += 1
        self.last_payload = {
            "organization_name": (
                organization_name
            ),
            "organization_slug": (
                organization_slug
            ),
            "display_name": (
                display_name
            ),
            "email": email,
            "password": password,
        }

        if self.conflict:
            raise (
                OrganizationSlugAlreadyExistsError(
                    (
                        "Organization slug "
                        "already exists"
                    )
                )
            )

        organization = (
            SimpleNamespace(
                id=ORGANIZATION_ID,
                name="Acme Security",
                slug="acme-security",
            )
        )

        user = SimpleNamespace(
            id=USER_ID,
            organization_id=(
                ORGANIZATION_ID
            ),
            email=(
                "security@example.test"
            ),
            display_name=(
                "Marie Curie"
            ),
            role=(
                "security_responsible"
            ),
        )

        return SimpleNamespace(
            organization=organization,
            user=user,
        )


def _client(
    service: FakeRegistrationService,
) -> TestClient:
    app = FastAPI()

    app.include_router(
        create_registration_router(
            service=service  # type: ignore[arg-type]
        )
    )

    return TestClient(
        app
    )


def _payload() -> dict[
    str,
    str,
]:
    return {
        "organization_name": (
            "Acme Security"
        ),
        "organization_slug": (
            "acme-security"
        ),
        "display_name": (
            "Marie Curie"
        ),
        "email": (
            "security@example.test"
        ),
        "password": (
            "secret-password"
        ),
    }


def test_register_endpoint_returns_created_registration(
) -> None:
    service = (
        FakeRegistrationService()
    )

    client = _client(
        service
    )

    response = client.post(
        "/api/v1/auth/register",
        json=_payload(),
    )

    assert (
        response.status_code
        == 201
    )

    body = response.json()

    assert (
        body["organization_id"]
        == str(ORGANIZATION_ID)
    )
    assert (
        body["organization_slug"]
        == "acme-security"
    )
    assert (
        body["user"]["user_id"]
        == str(USER_ID)
    )
    assert (
        body["user"]["role"]
        == "security_responsible"
    )

    assert service.calls == 1


def test_register_endpoint_maps_slug_conflict_to_409(
) -> None:
    service = (
        FakeRegistrationService(
            conflict=True
        )
    )

    client = _client(
        service
    )

    response = client.post(
        "/api/v1/auth/register",
        json=_payload(),
    )

    assert (
        response.status_code
        == 409
    )

    assert response.json() == {
        "detail": (
            "Organization slug "
            "already exists"
        )
    }


@pytest.mark.parametrize(
    "extra_field,extra_value",
    (
        (
            "role",
            "staff",
        ),
        (
            "organization_id",
            str(ORGANIZATION_ID),
        ),
    ),
)
def test_register_endpoint_forbids_client_controlled_identity_fields(
    extra_field: str,
    extra_value: str,
) -> None:
    service = (
        FakeRegistrationService()
    )

    client = _client(
        service
    )

    payload = _payload()
    payload[
        extra_field
    ] = extra_value

    response = client.post(
        "/api/v1/auth/register",
        json=payload,
    )

    assert (
        response.status_code
        == 422
    )
    assert service.calls == 0