from __future__ import annotations

from datetime import (
    UTC,
    datetime,
)
from unittest.mock import Mock
from uuid import (
    UUID,
    uuid4,
)

from fastapi.testclient import (
    TestClient,
)

from application.security.machine_api_key_authenticator import (
    MachineApiKeyAuthenticator,
)
from application.services.import_machine_inventory_service import (
    ImportMachineInventoryResult,
    ImportMachineInventoryService,
)
from infrastructure.api.app import (
    create_app,
)


NOW = datetime(
    2026,
    8,
    20,
    14,
    0,
    tzinfo=UTC,
)


def _payload(
    *,
    machine_uid: UUID,
) -> dict:
    return {
        "schema_version": (
            "inventory/v1"
        ),
        "inventory_id": str(
            uuid4()
        ),
        "collected_at": (
            NOW.isoformat()
        ),
        "agent": {
            "name": (
                "tip-windows-agent"
            ),
            "version": (
                "0.1.0"
            ),
        },
        "machine": {
            "machine_uid": str(
                machine_uid
            ),
            "hostname": (
                "TEST-PC"
            ),
            "os_name": (
                "Windows 11 Pro"
            ),
            "os_version": (
                "25H2"
            ),
            "architecture": (
                "x86_64"
            ),
        },
        "components": [],
    }


def _client() -> tuple[
    TestClient,
    Mock,
]:
    service = Mock(
        spec=(
            ImportMachineInventoryService
        )
    )

    service.import_inventory.return_value = (
        ImportMachineInventoryResult(
            machine_id=uuid4(),
            inventory_id=uuid4(),
            status="imported",
            machine_created=True,
            inserted_components=0,
            updated_components=0,
            deleted_components=0,
            component_count=0,
        )
    )

    authenticator = Mock(
        spec=(
            MachineApiKeyAuthenticator
        )
    )

    app = create_app(
        import_service=(
            service
        ),
        authenticator=(
            authenticator
        ),
    )

    return (
        TestClient(
            app
        ),
        service,
    )


def test_inventory_import_uses_organization_header(
) -> None:
    client, service = (
        _client()
    )

    organization_id = uuid4()
    machine_uid = uuid4()

    response = client.post(
        "/api/v1/inventory-imports",
        headers={
            "X-Organization-Id": str(
                organization_id
            ),
        },
        json=_payload(
            machine_uid=(
                machine_uid
            )
        ),
    )

    assert (
        response.status_code
        == 200
    )

    (
        service
        .import_inventory
        .assert_called_once()
    )

    call = (
        service
        .import_inventory
        .call_args
    )

    assert (
        call.kwargs[
            "organization_id"
        ]
        == organization_id
    )

    inventory = (
        call.kwargs[
            "inventory_payload"
        ]
    )

    assert (
        inventory
        .machine
        .machine_uid
        == machine_uid
    )

    assert (
        inventory.schema_version
        == "inventory/v1"
    )


def test_inventory_import_returns_result(
) -> None:
    client, service = (
        _client()
    )

    result = (
        ImportMachineInventoryResult(
            machine_id=uuid4(),
            inventory_id=uuid4(),
            status="imported",
            machine_created=True,
            inserted_components=12,
            updated_components=3,
            deleted_components=2,
            component_count=13,
        )
    )

    service.import_inventory.return_value = (
        result
    )

    response = client.post(
        "/api/v1/inventory-imports",
        headers={
            "X-Organization-Id": str(
                uuid4()
            ),
        },
        json=_payload(
            machine_uid=(
                uuid4()
            )
        ),
    )

    assert (
        response.status_code
        == 200
    )

    payload = (
        response.json()
    )

    assert (
        payload[
            "machine_id"
        ]
        == str(
            result.machine_id
        )
    )

    assert (
        payload[
            "inventory_id"
        ]
        == str(
            result.inventory_id
        )
    )

    assert (
        payload[
            "status"
        ]
        == "imported"
    )

    assert (
        payload[
            "machine_created"
        ]
        is True
    )

    assert (
        payload[
            "inserted_components"
        ]
        == 12
    )

    assert (
        payload[
            "updated_components"
        ]
        == 3
    )

    assert (
        payload[
            "deleted_components"
        ]
        == 2
    )

    assert (
        payload[
            "component_count"
        ]
        == 13
    )


def test_inventory_import_requires_organization_header(
) -> None:
    client, service = (
        _client()
    )

    response = client.post(
        "/api/v1/inventory-imports",
        json=_payload(
            machine_uid=(
                uuid4()
            )
        ),
    )

    assert (
        response.status_code
        == 422
    )

    (
        service
        .import_inventory
        .assert_not_called()
    )


def test_inventory_import_rejects_invalid_contract(
) -> None:
    client, service = (
        _client()
    )

    response = client.post(
        "/api/v1/inventory-imports",
        headers={
            "X-Organization-Id": str(
                uuid4()
            ),
        },
        json={
            "schema_version": (
                "wrong-version"
            ),
        },
    )

    assert (
        response.status_code
        == 422
    )

    (
        service
        .import_inventory
        .assert_not_called()
    )