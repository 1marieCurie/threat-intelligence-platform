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
from application.services.user_authentication_service import (
    UserAuthenticationService,
)
from domain.user_account import (
    UserAccount,
)
from infrastructure.api.app import (
    create_app,
)


ORGANIZATION_ID = uuid4()

USER_ID = uuid4()

NOW = datetime(
    2026,
    8,
    21,
    20,
    0,
    tzinfo=UTC,
)


def _user(
    *,
    role: str,
    organization_id: UUID = (
        ORGANIZATION_ID
    ),
) -> UserAccount:
    return UserAccount(
        id=USER_ID,
        organization_id=(
            organization_id
        ),
        email=(
            "security@tip.local"
            if role
            == "security_responsible"
            else "staff@tip.local"
        ),
        display_name=(
            "Test User"
        ),
        role=role,
        is_active=True,
        created_at=NOW,
    )


def _client(
    dashboard_service: (
        GetDashboardSummaryService
    ),
    *,
    authenticated_user: (
        UserAccount | None
    ) = None,
) -> tuple[
    TestClient,
    Mock,
]:
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

    authentication_service = Mock(
        spec=(
            UserAuthenticationService
        )
    )

    if authenticated_user is not None:
        (
            authentication_service
            .authenticate_access_token
            .return_value
        ) = authenticated_user

    app = create_app(
        import_service=(
            import_service
        ),
        authenticator=(
            authenticator
        ),
        dashboard_service=(
            dashboard_service
        ),
        authentication_service=(
            authentication_service
        ),
    )

    return (
        TestClient(app),
        authentication_service,
    )


def _summary(
) -> DashboardSummary:
    return DashboardSummary(
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


def test_dashboard_returns_summary_for_security_responsible(
) -> None:
    dashboard_service = Mock(
        spec=(
            GetDashboardSummaryService
        )
    )

    dashboard_service.get_summary.return_value = (
        _summary()
    )

    (
        client,
        authentication_service,
    ) = _client(
        dashboard_service,
        authenticated_user=(
            _user(
                role=(
                    "security_responsible"
                )
            )
        ),
    )

    response = client.get(
        "/api/v1/dashboard",
        headers={
            "Authorization": (
                "Bearer security-token"
            ),
        },
    )

    assert (
        response.status_code
        == 200
    )

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
        authentication_service
        .authenticate_access_token
        .assert_called_once_with(
            access_token=(
                "security-token"
            )
        )
    )

    (
        dashboard_service
        .get_summary
        .assert_called_once_with(
            organization_id=(
                ORGANIZATION_ID
            )
        )
    )


def test_dashboard_requires_authentication(
) -> None:
    dashboard_service = Mock(
        spec=(
            GetDashboardSummaryService
        )
    )

    (
        client,
        authentication_service,
    ) = _client(
        dashboard_service
    )

    response = client.get(
        "/api/v1/dashboard"
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

    (
        dashboard_service
        .get_summary
        .assert_not_called()
    )


def test_dashboard_rejects_staff(
) -> None:
    dashboard_service = Mock(
        spec=(
            GetDashboardSummaryService
        )
    )

    (
        client,
        _,
    ) = _client(
        dashboard_service,
        authenticated_user=(
            _user(
                role="staff"
            )
        ),
    )

    response = client.get(
        "/api/v1/dashboard",
        headers={
            "Authorization": (
                "Bearer staff-token"
            ),
        },
    )

    assert (
        response.status_code
        == 403
    )

    assert response.json() == {
        "detail": (
            "Security responsible "
            "role required"
        )
    }

    (
        dashboard_service
        .get_summary
        .assert_not_called()
    )


def test_dashboard_ignores_spoofed_organization_header(
) -> None:
    authenticated_organization_id = (
        uuid4()
    )

    spoofed_organization_id = (
        uuid4()
    )

    dashboard_service = Mock(
        spec=(
            GetDashboardSummaryService
        )
    )

    dashboard_service.get_summary.return_value = (
        _summary()
    )

    (
        client,
        _,
    ) = _client(
        dashboard_service,
        authenticated_user=(
            _user(
                role=(
                    "security_responsible"
                ),
                organization_id=(
                    authenticated_organization_id
                ),
            )
        ),
    )

    response = client.get(
        "/api/v1/dashboard",
        headers={
            "Authorization": (
                "Bearer security-token"
            ),
            "X-Organization-Id": str(
                spoofed_organization_id
            ),
        },
    )

    assert (
        response.status_code
        == 200
    )

    (
        dashboard_service
        .get_summary
        .assert_called_once_with(
            organization_id=(
                authenticated_organization_id
            )
        )
    )


def test_dashboard_maps_repository_error_to_503(
) -> None:
    dashboard_service = Mock(
        spec=(
            GetDashboardSummaryService
        )
    )

    (
        dashboard_service
        .get_summary
        .side_effect
    ) = DashboardReadRepositoryError(
        "database unavailable"
    )

    (
        client,
        _,
    ) = _client(
        dashboard_service,
        authenticated_user=(
            _user(
                role=(
                    "security_responsible"
                )
            )
        ),
    )

    response = client.get(
        "/api/v1/dashboard",
        headers={
            "Authorization": (
                "Bearer security-token"
            ),
        },
    )

    assert (
        response.status_code
        == 503
    )

    assert response.json() == {
        "detail": (
            "Dashboard service is "
            "temporarily unavailable"
        )
    }