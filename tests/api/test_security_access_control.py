from __future__ import annotations

from datetime import (
    UTC,
    datetime,
)
from types import SimpleNamespace
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
from application.services.analyze_url_service import (
    AnalyzeURLService,
)
from application.services.get_alert_detail_service import (
    GetAlertDetailService,
)
from application.services.get_dashboard_summary_service import (
    GetDashboardSummaryService,
)
from application.services.get_machine_detail_service import (
    GetMachineDetailService,
)
from application.services.get_vulnerability_detail_service import (
    GetVulnerabilityDetailService,
)
from application.services.import_machine_inventory_service import (
    ImportMachineInventoryService,
)
from application.services.list_alerts_service import (
    ListAlertsService,
)
from application.services.list_machines_service import (
    ListMachinesService,
)
from application.services.list_software_service import (
    ListSoftwareService,
)
from application.services.list_vulnerabilities_service import (
    ListVulnerabilitiesService,
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

NOW = datetime(
    2026,
    8,
    21,
    20,
    30,
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
        id=uuid4(),
        organization_id=(
            organization_id
        ),
        email=(
            "security@tip.local"
            if role
            == "security_responsible"
            else "staff@tip.local"
        ),
        display_name="Test User",
        role=role,
        is_active=True,
        created_at=NOW,
    )


def _client(
    *,
    user: UserAccount,
) -> tuple[
    TestClient,
    dict[str, Mock],
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

    (
        authentication_service
        .authenticate_access_token
        .return_value
    ) = user

    analyze_service = Mock(
        spec=AnalyzeURLService
    )

    (
        analyze_service
        .analyze
        .return_value
    ) = SimpleNamespace(
        verdict="benign",
        threat_class="benign",
        confidence=0.95,
        model_version="test",
    )

    dashboard_service = Mock(
        spec=(
            GetDashboardSummaryService
        )
    )

    machines_service = Mock(
        spec=ListMachinesService
    )

    machines_service.list_machines.return_value = ()

    machine_detail_service = Mock(
        spec=(
            GetMachineDetailService
        )
    )

    software_service = Mock(
        spec=ListSoftwareService
    )

    software_service.list_software.return_value = ()

    vulnerabilities_service = Mock(
        spec=(
            ListVulnerabilitiesService
        )
    )

    (
        vulnerabilities_service
        .list_vulnerabilities
        .return_value
    ) = ()

    vulnerability_detail_service = Mock(
        spec=(
            GetVulnerabilityDetailService
        )
    )

    alerts_service = Mock(
        spec=ListAlertsService
    )

    alerts_service.list_alerts.return_value = ()

    alert_detail_service = Mock(
        spec=GetAlertDetailService
    )

    app = create_app(
        import_service=import_service,
        authenticator=(
            machine_authenticator
        ),
        analyze_url_service=(
            analyze_service
        ),
        machines_service=(
            machines_service
        ),
        machine_detail_service=(
            machine_detail_service
        ),
        software_service=(
            software_service
        ),
        vulnerabilities_service=(
            vulnerabilities_service
        ),
        vulnerability_detail_service=(
            vulnerability_detail_service
        ),
        alerts_service=(
            alerts_service
        ),
        alert_detail_service=(
            alert_detail_service
        ),
        authentication_service=(
            authentication_service
        ),
    )

    return (
        TestClient(app),
        {
            "auth": (
                authentication_service
            ),
            "machines": (
                machines_service
            ),
            "software": (
                software_service
            ),
            "vulnerabilities": (
                vulnerabilities_service
            ),
            "alerts": (
                alerts_service
            ),
            "analyze": (
                analyze_service
            ),
        },
    )


def _auth_headers(
    token: str = "token",
) -> dict[str, str]:
    return {
        "Authorization": (
            f"Bearer {token}"
        )
    }


def test_security_responsible_can_read_security_cockpit(
) -> None:
    (
        client,
        services,
    ) = _client(
        user=_user(
            role=(
                "security_responsible"
            )
        )
    )

    paths = (
        "/api/v1/machines",
        "/api/v1/software",
        "/api/v1/vulnerabilities",
        "/api/v1/alerts",
    )

    for path in paths:
        response = client.get(
            path,
            headers=_auth_headers(),
        )

        assert (
            response.status_code
            == 200
        ), path

    (
        services["machines"]
        .list_machines
        .assert_called_once_with(
            organization_id=(
                ORGANIZATION_ID
            )
        )
    )

    (
        services["software"]
        .list_software
        .assert_called_once_with(
            organization_id=(
                ORGANIZATION_ID
            )
        )
    )

    (
        services["vulnerabilities"]
        .list_vulnerabilities
        .assert_called_once_with(
            organization_id=(
                ORGANIZATION_ID
            )
        )
    )

    (
        services["alerts"]
        .list_alerts
        .assert_called_once_with(
            organization_id=(
                ORGANIZATION_ID
            )
        )
    )


def test_staff_is_forbidden_from_security_cockpit(
) -> None:
    (
        client,
        _,
    ) = _client(
        user=_user(
            role="staff"
        )
    )

    paths = (
        "/api/v1/machines",
        "/api/v1/software",
        "/api/v1/vulnerabilities",
        "/api/v1/alerts",
        (
            "/api/v1/"
            "inventory-agent/windows/script"
        ),
    )

    for path in paths:
        response = client.get(
            path,
            headers=_auth_headers(
                "staff-token"
            ),
        )

        assert (
            response.status_code
            == 403
        ), path


def test_staff_can_analyze_url(
) -> None:
    (
        client,
        services,
    ) = _client(
        user=_user(
            role="staff"
        )
    )

    response = client.post(
        "/api/v1/url-analysis",
        headers=_auth_headers(
            "staff-token"
        ),
        json={
            "url": (
                "https://example.com"
            )
        },
    )

    assert (
        response.status_code
        == 200
    )

    assert (
        response.json()["verdict"]
        == "benign"
    )

    (
        services["analyze"]
        .analyze
        .assert_called_once_with(
            "https://example.com"
        )
    )


def test_security_responsible_can_analyze_url(
) -> None:
    (
        client,
        _,
    ) = _client(
        user=_user(
            role=(
                "security_responsible"
            )
        )
    )

    response = client.post(
        "/api/v1/url-analysis",
        headers=_auth_headers(
            "security-token"
        ),
        json={
            "url": (
                "https://example.com"
            )
        },
    )

    assert (
        response.status_code
        == 200
    )


def test_url_analysis_requires_authentication(
) -> None:
    (
        client,
        services,
    ) = _client(
        user=_user(
            role="staff"
        )
    )

    response = client.post(
        "/api/v1/url-analysis",
        json={
            "url": (
                "https://example.com"
            )
        },
    )

    assert (
        response.status_code
        == 401
    )

    (
        services["analyze"]
        .analyze
        .assert_not_called()
    )


def test_spoofed_organization_header_is_ignored(
) -> None:
    real_organization_id = (
        uuid4()
    )

    spoofed_organization_id = (
        uuid4()
    )

    (
        client,
        services,
    ) = _client(
        user=_user(
            role=(
                "security_responsible"
            ),
            organization_id=(
                real_organization_id
            ),
        )
    )

    response = client.get(
        "/api/v1/machines",
        headers={
            **_auth_headers(
                "security-token"
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
        services["machines"]
        .list_machines
        .assert_called_once_with(
            organization_id=(
                real_organization_id
            )
        )
    )