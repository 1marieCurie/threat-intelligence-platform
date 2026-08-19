from __future__ import annotations

from unittest.mock import Mock
from uuid import uuid4

from fastapi.testclient import TestClient

from application.models.dashboard import (
    DashboardPriorityDistribution,
    DashboardSummary,
)
from application.ports.outbound.dashboard_read_repository import (
    DashboardReadRepositoryError,
)
from application.security.machine_api_key_authenticator import (
    MachineApiKeyAuthenticator,
)
from application.services.get_dashboard_summary_service import (
    GetDashboardSummaryService,
)
from application.services.import_machine_inventory_service import (
    ImportMachineInventoryService,
)
from infrastructure.api.app import (
    create_app,
)


def _client(
    dashboard_service: GetDashboardSummaryService,
) -> TestClient:
    import_service = Mock(
        spec=ImportMachineInventoryService
    )

    authenticator = Mock(
        spec=MachineApiKeyAuthenticator
    )

    app = create_app(
        import_service=import_service,
        authenticator=authenticator,
        dashboard_service=dashboard_service,
    )

    return TestClient(app)


def test_dashboard_returns_summary() -> None:
    organization_id = uuid4()

    dashboard_service = Mock(
        spec=GetDashboardSummaryService
    )

    dashboard_service.get_summary.return_value = (
        DashboardSummary(
            machine_count=4,
            component_count=25,
            confirmed_exposure_count=7,
            potential_exposure_count=3,
            critical_exposure_count=2,
            kev_exposure_count=1,
            pending_alert_count=2,
            failed_alert_count=1,
            priority_distribution=(
                DashboardPriorityDistribution(
                    low=1,
                    medium=3,
                    high=4,
                    critical=2,
                )
            ),
            top_machines=(),
            priority_actions=(),
            latest_alerts=(),
        )
    )

    client = _client(
        dashboard_service
    )

    response = client.get(
        "/api/v1/dashboard",
        headers={
            "X-Organization-Id": str(
                organization_id
            ),
        },
    )

    assert response.status_code == 200

    assert response.json() == {
        "machine_count": 4,
        "component_count": 25,
        "confirmed_exposure_count": 7,
        "potential_exposure_count": 3,
        "critical_exposure_count": 2,
        "kev_exposure_count": 1,
        "pending_alert_count": 2,
        "failed_alert_count": 1,
        "priority_distribution": {
            "low": 1,
            "medium": 3,
            "high": 4,
            "critical": 2,
        },
        "top_machines": [],
        "priority_actions": [],
        "latest_alerts": [],
    }

    (
        dashboard_service
        .get_summary
        .assert_called_once_with(
            organization_id=organization_id
        )
    )


def test_dashboard_requires_organization_header(
) -> None:
    dashboard_service = Mock(
        spec=GetDashboardSummaryService
    )

    client = _client(
        dashboard_service
    )

    response = client.get(
        "/api/v1/dashboard"
    )

    assert response.status_code == 422

    dashboard_service.get_summary.assert_not_called()


def test_dashboard_maps_repository_error_to_503(
) -> None:
    dashboard_service = Mock(
        spec=GetDashboardSummaryService
    )

    dashboard_service.get_summary.side_effect = (
        DashboardReadRepositoryError(
            "database unavailable"
        )
    )

    client = _client(
        dashboard_service
    )

    response = client.get(
        "/api/v1/dashboard",
        headers={
            "X-Organization-Id": str(
                uuid4()
            ),
        },
    )

    assert response.status_code == 503

    assert response.json() == {
        "detail": (
            "Dashboard service is "
            "temporarily unavailable"
        )
    }