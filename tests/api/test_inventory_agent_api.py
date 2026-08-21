from __future__ import annotations

from unittest.mock import Mock
from uuid import uuid4

from fastapi.testclient import (
    TestClient,
)

from application.security.machine_api_key_authenticator import (
    MachineApiKeyAuthenticator,
)
from application.services.import_machine_inventory_service import (
    ImportMachineInventoryService,
)
from infrastructure.api.app import (
    create_app,
)
from tests.api.auth_test_support import (
    allow_security_user,
)


def _client() -> TestClient:
    import_service = Mock(
        spec=(
            ImportMachineInventoryService
        )
    )

    authenticator = Mock(
        spec=(
            MachineApiKeyAuthenticator
        )
    )

    app = create_app(
        import_service=import_service,
        authenticator=authenticator,
    )

    allow_security_user(
        app,
        organization_id=uuid4(),
    )

    return TestClient(app)


def test_windows_inventory_script_is_available(
) -> None:
    client = _client()

    response = client.get(
        "/api/v1/inventory-agent/windows/script"
    )

    assert response.status_code == 200

    assert (
        response.headers[
            "content-type"
        ].startswith(
            "text/plain"
        )
    )


def test_windows_inventory_script_is_current_v1_collector(
) -> None:
    client = _client()

    response = client.get(
        "/api/v1/inventory-agent/windows/script"
    )

    assert response.status_code == 200

    script = response.text

    assert (
        "[CmdletBinding()]"
        in script
    )

    assert (
        '$SchemaVersion = "inventory/v1"'
        in script
    )

    assert (
        '$AgentVersion = "0.2.0"'
        in script
    )

    assert (
        "Get-InstalledApplicationComponents"
        in script
    )

    assert (
        "Get-GlobalPythonPackageComponents"
        in script
    )

    assert (
        "Get-GlobalNpmPackageComponents"
        in script
    )