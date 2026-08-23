from __future__ import annotations

from unittest.mock import Mock
from uuid import (
    UUID,
    uuid4,
)

from fastapi.testclient import (
    TestClient,
)

from application.models.software_view import (
    SoftwareSummary,
)
from application.ports.outbound.software_read_repository import (
    SoftwareReadRepositoryError,
)
from application.security.machine_api_key_authenticator import (
    MachineApiKeyAuthenticator,
)
from application.services.import_machine_inventory_service import (
    ImportMachineInventoryService,
)
from application.services.list_software_service import (
    ListSoftwareService,
)
from infrastructure.api.app import (
    create_app,
)
from tests.api.auth_test_support import (
    allow_security_user,
)


def _client(
    software_service: ListSoftwareService,
    *,
    organization_id: UUID,
) -> TestClient:
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
        software_service=(
            software_service
        ),
    )

    allow_security_user(
        app,
        organization_id=(
            organization_id
        ),
    )

    return TestClient(app)


def test_list_software_returns_items(
) -> None:
    organization_id = uuid4()

    software_service = Mock(
        spec=ListSoftwareService
    )

    software_service.list_software.return_value = (
        SoftwareSummary(
            component_type="application",
            name="Node.js",
            version="22.22.0",
            vendor=(
                "Node.js Foundation"
            ),
            ecosystem=None,
            machine_count=2,
            exposure_count=3,
        ),
    )

    client = _client(
        software_service,
        organization_id=(
            organization_id
        ),
    )

    response = client.get(
        "/api/v1/software"
    )

    assert response.status_code == 200

    assert response.json() == {
        "items": [
            {
                "component_type":
                    "application",
                "name": "Node.js",
                "version": "22.22.0",
                "vendor":
                    "Node.js Foundation",
                "ecosystem": None,
                "machine_count": 2,
                "exposure_count": 3,
            }
        ]
    }

    (
        software_service
        .list_software
        .assert_called_once_with(
            organization_id=(
                organization_id
            )
        )
    )


def test_list_software_maps_repository_error_to_503(
) -> None:
    organization_id = uuid4()

    software_service = Mock(
        spec=ListSoftwareService
    )

    software_service.list_software.side_effect = (
        SoftwareReadRepositoryError(
            "database unavailable"
        )
    )

    client = _client(
        software_service,
        organization_id=(
            organization_id
        ),
    )

    response = client.get(
        "/api/v1/software"
    )

    assert response.status_code == 503

    assert response.json() == {
        "detail": (
            "Software service is "
            "temporarily unavailable"
        )
    }