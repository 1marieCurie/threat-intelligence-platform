from __future__ import annotations

from datetime import (
    UTC,
    datetime,
)
from unittest.mock import Mock
from uuid import uuid4

from fastapi.testclient import TestClient

from application.models.machine_view import (
    MachineDetail,
    MachineSummary,
)
from application.ports.outbound.machine_read_repository import (
    MachineReadRepositoryError,
)
from application.security.machine_api_key_authenticator import (
    MachineApiKeyAuthenticator,
)
from application.services.get_machine_detail_service import (
    GetMachineDetailService,
)
from application.services.import_machine_inventory_service import (
    ImportMachineInventoryService,
)
from application.services.list_machines_service import (
    ListMachinesService,
)
from infrastructure.api.app import (
    create_app,
)


def _client(
    machines_service: ListMachinesService,
    detail_service: (
        GetMachineDetailService | None
    ) = None,
) -> TestClient:
    import_service = Mock(
        spec=ImportMachineInventoryService
    )

    authenticator = Mock(
        spec=MachineApiKeyAuthenticator
    )

    if detail_service is None:
        detail_service = Mock(
            spec=GetMachineDetailService
        )

    app = create_app(
        import_service=import_service,
        authenticator=authenticator,
        machines_service=machines_service,
        machine_detail_service=detail_service,
    )

    return TestClient(app)


def test_list_machines_returns_items(
) -> None:
    organization_id = uuid4()
    machine_id = uuid4()

    machines_service = Mock(
        spec=ListMachinesService
    )

    machines_service.list_machines.return_value = (
        MachineSummary(
            machine_id=machine_id,
            hostname="workstation-01",
            os_name="Windows",
            os_version="11",
            architecture="x64",
            last_inventory_at=datetime(
                2026,
                8,
                19,
                12,
                0,
                tzinfo=UTC,
            ),
            component_count=12,
            exposure_count=4,
            critical_exposure_count=1,
            kev_exposure_count=1,
        ),
    )

    client = _client(
        machines_service
    )

    response = client.get(
        "/api/v1/machines",
        headers={
            "X-Organization-Id": str(
                organization_id
            ),
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert len(
        payload["items"]
    ) == 1

    item = payload["items"][0]

    assert (
        item["machine_id"]
        == str(machine_id)
    )

    assert (
        item["hostname"]
        == "workstation-01"
    )

    assert (
        item["os_name"]
        == "Windows"
    )

    assert (
        item["os_version"]
        == "11"
    )

    assert (
        item["architecture"]
        == "x64"
    )

    assert (
        item["component_count"]
        == 12
    )

    assert (
        item["exposure_count"]
        == 4
    )

    assert (
        item[
            "critical_exposure_count"
        ]
        == 1
    )

    assert (
        item["kev_exposure_count"]
        == 1
    )

    (
        machines_service
        .list_machines
        .assert_called_once_with(
            organization_id=(
                organization_id
            )
        )
    )


def test_list_machines_requires_organization_header(
) -> None:
    machines_service = Mock(
        spec=ListMachinesService
    )

    client = _client(
        machines_service
    )

    response = client.get(
        "/api/v1/machines"
    )

    assert response.status_code == 422

    (
        machines_service
        .list_machines
        .assert_not_called()
    )


def test_list_machines_maps_repository_error_to_503(
) -> None:
    machines_service = Mock(
        spec=ListMachinesService
    )

    machines_service.list_machines.side_effect = (
        MachineReadRepositoryError(
            "database unavailable"
        )
    )

    client = _client(
        machines_service
    )

    response = client.get(
        "/api/v1/machines",
        headers={
            "X-Organization-Id": str(
                uuid4()
            ),
        },
    )

    assert response.status_code == 503

    assert response.json() == {
        "detail": (
            "Machine service is "
            "temporarily unavailable"
        )
    }


def test_get_machine_returns_detail(
) -> None:
    organization_id = uuid4()
    machine_id = uuid4()
    machine_uid = uuid4()

    machines_service = Mock(
        spec=ListMachinesService
    )

    detail_service = Mock(
        spec=GetMachineDetailService
    )

    detail_service.get_machine.return_value = (
        MachineDetail(
            machine_id=machine_id,
            machine_uid=machine_uid,
            hostname="workstation-01",
            os_name="Windows 11 Pro",
            os_version="25H2",
            architecture="x86_64",
            last_inventory_at=datetime(
                2026,
                8,
                19,
                12,
                0,
                tzinfo=UTC,
            ),
            components=(),
            exposures=(),
        )
    )

    client = _client(
        machines_service,
        detail_service,
    )

    response = client.get(
        f"/api/v1/machines/{machine_id}",
        headers={
            "X-Organization-Id": str(
                organization_id
            ),
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert (
        payload["machine_id"]
        == str(machine_id)
    )

    assert (
        payload["machine_uid"]
        == str(machine_uid)
    )

    assert (
        payload["hostname"]
        == "workstation-01"
    )

    assert (
        payload["os_name"]
        == "Windows 11 Pro"
    )

    assert (
        payload["os_version"]
        == "25H2"
    )

    assert (
        payload["architecture"]
        == "x86_64"
    )

    assert payload["components"] == []
    assert payload["exposures"] == []

    (
        detail_service
        .get_machine
        .assert_called_once_with(
            organization_id=(
                organization_id
            ),
            machine_id=(
                machine_id
            ),
        )
    )


def test_get_machine_returns_404_when_not_found(
) -> None:
    organization_id = uuid4()
    machine_id = uuid4()

    machines_service = Mock(
        spec=ListMachinesService
    )

    detail_service = Mock(
        spec=GetMachineDetailService
    )

    detail_service.get_machine.return_value = (
        None
    )

    client = _client(
        machines_service,
        detail_service,
    )

    response = client.get(
        f"/api/v1/machines/{machine_id}",
        headers={
            "X-Organization-Id": str(
                organization_id
            ),
        },
    )

    assert response.status_code == 404

    assert response.json() == {
        "detail": "Machine not found"
    }

    (
        detail_service
        .get_machine
        .assert_called_once_with(
            organization_id=(
                organization_id
            ),
            machine_id=(
                machine_id
            ),
        )
    )