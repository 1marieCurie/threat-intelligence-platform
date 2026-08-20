from __future__ import annotations

from datetime import (
    UTC,
    datetime,
)
from unittest.mock import Mock
from uuid import uuid4

from fastapi.testclient import (
    TestClient,
)

from application.models.alert_view import (
    AlertSummary,
)
from application.ports.outbound.alert_read_repository import (
    AlertReadRepositoryError,
)
from application.security.machine_api_key_authenticator import (
    MachineApiKeyAuthenticator,
)
from application.services.import_machine_inventory_service import (
    ImportMachineInventoryService,
)
from application.services.list_alerts_service import (
    ListAlertsService,
)
from infrastructure.api.app import (
    create_app,
)


def _client(
    service: ListAlertsService,
) -> TestClient:
    import_service = Mock(
        spec=ImportMachineInventoryService
    )

    authenticator = Mock(
        spec=MachineApiKeyAuthenticator
    )

    app = create_app(
        import_service=(
            import_service
        ),
        authenticator=(
            authenticator
        ),
        alerts_service=(
            service
        ),
    )

    return TestClient(
        app
    )


def test_list_alerts_returns_items(
) -> None:
    organization_id = uuid4()

    alert_id = uuid4()
    machine_id = uuid4()
    canonical_id = uuid4()

    created_at = datetime(
        2026,
        8,
        20,
        12,
        0,
        tzinfo=UTC,
    )

    sent_at = datetime(
        2026,
        8,
        20,
        12,
        1,
        tzinfo=UTC,
    )

    service = Mock(
        spec=ListAlertsService
    )

    service.list_alerts.return_value = (
        AlertSummary(
            alert_id=(
                alert_id
            ),
            alert_type=(
                "priority_transition_"
                "to_critical"
            ),
            status="sent",
            created_at=(
                created_at
            ),
            sent_at=(
                sent_at
            ),
            machine_id=(
                machine_id
            ),
            machine_hostname=(
                "PC-FINANCE-01"
            ),
            canonical_vulnerability_id=(
                canonical_id
            ),
            primary_identifier=(
                "CVE-2026-12345"
            ),
            component_name=(
                "Example Software"
            ),
            component_version=(
                "4.2.1"
            ),
            current_priority=(
                "CRITICAL"
            ),
            is_kev=True,
        ),
    )

    client = _client(
        service
    )

    response = client.get(
        "/api/v1/alerts",
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
        item["alert_id"]
        == str(
            alert_id
        )
    )

    assert (
        item["alert_type"]
        == (
            "priority_transition_"
            "to_critical"
        )
    )

    assert (
        item["status"]
        == "sent"
    )

    assert (
        item["machine_hostname"]
        == "PC-FINANCE-01"
    )

    assert (
        item["primary_identifier"]
        == "CVE-2026-12345"
    )

    assert (
        item["component_name"]
        == "Example Software"
    )

    assert (
        item["component_version"]
        == "4.2.1"
    )

    assert (
        item["current_priority"]
        == "CRITICAL"
    )

    assert (
        item["is_kev"]
        is True
    )

    (
        service
        .list_alerts
        .assert_called_once_with(
            organization_id=(
                organization_id
            )
        )
    )


def test_list_alerts_requires_header(
) -> None:
    service = Mock(
        spec=ListAlertsService
    )

    client = _client(
        service
    )

    response = client.get(
        "/api/v1/alerts"
    )

    assert (
        response.status_code
        == 422
    )


def test_list_alerts_maps_repository_error(
) -> None:
    service = Mock(
        spec=ListAlertsService
    )

    service.list_alerts.side_effect = (
        AlertReadRepositoryError(
            "database unavailable"
        )
    )

    client = _client(
        service
    )

    response = client.get(
        "/api/v1/alerts",
        headers={
            "X-Organization-Id": str(
                uuid4()
            ),
        },
    )

    assert (
        response.status_code
        == 503
    )

    assert response.json() == {
        "detail": (
            "Alert service is "
            "temporarily unavailable"
        )
    }