from __future__ import annotations

from unittest.mock import Mock

from fastapi.testclient import (
    TestClient,
)

from application.security.machine_api_key_authenticator import (
    MachineApiKeyAuthenticator,
)
from application.services.import_machine_inventory_service import (
    ImportMachineInventoryService,
)
from application.services.user_authentication_service import (
    UserAuthenticationService,
)
from infrastructure.api.app import (
    create_app,
)


def _build_client() -> tuple[
    TestClient,
    Mock,
]:
    import_service = Mock(
        spec=(
            ImportMachineInventoryService
        )
    )

    machine_authenticator = Mock(
        spec=(
            MachineApiKeyAuthenticator
        )
    )

    authentication_service = Mock(
        spec=(
            UserAuthenticationService
        )
    )

    app = create_app(
        import_service=(
            import_service
        ),
        authenticator=(
            machine_authenticator
        ),
        authentication_service=(
            authentication_service
        ),
        auth_refresh_token_ttl_seconds=(
            30 * 24 * 60 * 60
        ),
        auth_cookie_secure=False,
    )

    return (
        TestClient(app),
        authentication_service,
    )


def test_auth_router_is_registered(
) -> None:
    (
        client,
        authentication_service,
    ) = _build_client()

    response = client.get(
        "/api/v1/auth/me"
    )

    assert (
        response.status_code
        == 401
    )

    (
        authentication_service
        .authenticate_access_token
        .assert_not_called()
    )


def test_health_remains_available(
) -> None:
    (
        client,
        _,
    ) = _build_client()

    response = client.get(
        "/health"
    )

    assert (
        response.status_code
        == 200
    )

    assert (
        response.json()
        == {
            "status": "ok",
        }
    )


def test_cors_allows_credentials_for_dev_frontend(
) -> None:
    (
        client,
        _,
    ) = _build_client()

    response = client.options(
        "/api/v1/auth/refresh",
        headers={
            "Origin": (
                "http://localhost:5173"
            ),
            "Access-Control-Request-Method": (
                "POST"
            ),
        },
    )

    assert (
        response.status_code
        == 200
    )

    assert (
        response.headers[
            "access-control-allow-origin"
        ]
        == "http://localhost:5173"
    )

    assert (
        response.headers[
            "access-control-allow-credentials"
        ]
        == "true"
    )