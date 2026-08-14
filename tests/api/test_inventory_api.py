from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import (
    Mock,
)
from uuid import UUID, uuid4

from fastapi.testclient import (
    TestClient,
)

from application.security.machine_api_key_authenticator import (
    MachineApiCredential,
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
    14,
    16,
    0,
    tzinfo=UTC,
)


def _payload(
    *,
    machine_uid: UUID,
) -> dict:
    return {
        "schema_version": "inventory/v1",
        "inventory_id": str(
            uuid4()
        ),
        "collected_at": (
            NOW.isoformat()
        ),
        "agent": {
            "name": "tip-windows-agent",
            "version": "0.1.0",
        },
        "machine": {
            "machine_uid": str(
                machine_uid
            ),
            "hostname": "TEST-PC",
            "os_name": "Windows 11 Pro",
            "os_version": "25H2",
            "architecture": "x86_64",
        },
        "components": [],
    }


def _client(
    *,
    api_key: str,
    organization_id: UUID,
    machine_uid: UUID,
) -> tuple[
    TestClient,
    Mock,
]:
    authenticator = (
        MachineApiKeyAuthenticator(
            [
                MachineApiCredential(
                    key_sha256=(
                        MachineApiKeyAuthenticator
                        .hash_api_key(
                            api_key
                        )
                    ),
                    organization_id=(
                        organization_id
                    ),
                    machine_uid=machine_uid,
                )
            ]
        )
    )

    service = Mock(
        spec=ImportMachineInventoryService
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

    app = create_app(
        import_service=service,
        authenticator=authenticator,
    )

    return (
        TestClient(app),
        service,
    )


def test_inventory_requires_machine_api_key(
) -> None:
    client, service = _client(
        api_key="valid-key",
        organization_id=uuid4(),
        machine_uid=uuid4(),
    )

    response = client.post(
        "/api/v1/inventories",
        json={},
    )

    assert response.status_code == 401

    service.import_inventory.assert_not_called()


def test_inventory_rejects_invalid_machine_api_key(
) -> None:
    machine_uid = uuid4()

    client, service = _client(
        api_key="valid-key",
        organization_id=uuid4(),
        machine_uid=machine_uid,
    )

    response = client.post(
        "/api/v1/inventories",
        headers={
            "Authorization": (
                "Bearer wrong-key"
            )
        },
        json=_payload(
            machine_uid=machine_uid
        ),
    )

    assert response.status_code == 401

    service.import_inventory.assert_not_called()


def test_inventory_rejects_machine_uid_spoofing(
) -> None:
    credential_machine_uid = uuid4()

    client, service = _client(
        api_key="valid-key",
        organization_id=uuid4(),
        machine_uid=(
            credential_machine_uid
        ),
    )

    response = client.post(
        "/api/v1/inventories",
        headers={
            "Authorization": (
                "Bearer valid-key"
            )
        },
        json=_payload(
            machine_uid=uuid4()
        ),
    )

    assert response.status_code == 403

    service.import_inventory.assert_not_called()


def test_inventory_uses_tenant_from_credential(
) -> None:
    organization_id = uuid4()
    machine_uid = uuid4()

    client, service = _client(
        api_key="valid-key",
        organization_id=(
            organization_id
        ),
        machine_uid=machine_uid,
    )

    response = client.post(
        "/api/v1/inventories",
        headers={
            "Authorization": (
                "Bearer valid-key"
            )
        },
        json=_payload(
            machine_uid=machine_uid
        ),
    )

    assert response.status_code == 200

    service.import_inventory.assert_called_once()

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
        inventory.machine.machine_uid
        == machine_uid
    )


def test_inventory_rejects_invalid_contract(
) -> None:
    machine_uid = uuid4()

    client, service = _client(
        api_key="valid-key",
        organization_id=uuid4(),
        machine_uid=machine_uid,
    )

    response = client.post(
        "/api/v1/inventories",
        headers={
            "Authorization": (
                "Bearer valid-key"
            )
        },
        json={
            "schema_version": "bad",
        },
    )

    assert response.status_code == 422

    service.import_inventory.assert_not_called()