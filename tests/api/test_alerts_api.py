from __future__ import annotations

from datetime import (
    UTC,
    datetime,
)
from unittest.mock import Mock
from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import (
    TestClient,
)

from application.models.alert_view import (
    AlertComponentView,
    AlertDetail,
    AlertExposureView,
    AlertIdentifierView,
    AlertMachineView,
    AlertRecipientView,
    AlertSummary,
    AlertWeaknessView,
)
from application.ports.outbound.alert_read_repository import (
    AlertReadRepositoryError,
)
from application.services.get_alert_detail_service import (
    GetAlertDetailService,
)
from application.services.list_alerts_service import (
    ListAlertsService,
)
from infrastructure.api.alerts_router import (
    create_alerts_router,
)


def _client(
    service: ListAlertsService,
    detail_service: (
        GetAlertDetailService
        | None
    ) = None,
) -> TestClient:
    app = FastAPI()

    app.include_router(
        create_alerts_router(
            service=service,
            detail_service=(
                detail_service
            ),
        )
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
            alert_id=alert_id,
            alert_type=(
                "priority_transition_"
                "to_critical"
            ),
            status="sent",
            created_at=created_at,
            sent_at=sent_at,
            machine_id=machine_id,
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
            component_version="4.2.1",
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
        == str(alert_id)
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


def _build_detail(
) -> AlertDetail:
    now = datetime(
        2026,
        8,
        20,
        14,
        0,
        tzinfo=UTC,
    )

    return AlertDetail(
        alert_id=uuid4(),
        alert_type=(
            "new_confirmed_critical_exposure"
        ),
        status="pending",
        created_at=now,
        sent_at=None,
        recipient=(
            AlertRecipientView(
                user_id=uuid4(),
                email=(
                    "security@example.test"
                ),
                display_name=(
                    "Security Responsible"
                ),
            )
        ),
        machine=(
            AlertMachineView(
                machine_id=uuid4(),
                hostname=(
                    "PC-SECURITY-01"
                ),
                os_name=(
                    "Windows 11 Pro"
                ),
                os_version="24H2",
                architecture="x86_64",
            )
        ),
        canonical_vulnerability_id=(
            uuid4()
        ),
        primary_identifier=(
            "CVE-2026-9999"
        ),
        identifiers=(
            AlertIdentifierView(
                namespace="CVE",
                value=(
                    "CVE-2026-9999"
                ),
                is_primary=True,
            ),
            AlertIdentifierView(
                namespace="GHSA",
                value=(
                    "GHSA-AAAA-BBBB-CCCC"
                ),
                is_primary=False,
            ),
        ),
        component=(
            AlertComponentView(
                component_id=uuid4(),
                component_type="package",
                name="requests",
                version="2.31.0",
                vendor=None,
                ecosystem="pypi",
                scope="global",
            )
        ),
        exposure=(
            AlertExposureView(
                exposure_id=uuid4(),
                applicability_status=(
                    "confirmed"
                ),
                severity="CRITICAL",
                priority="CRITICAL",
                is_kev=True,
                match_rule=(
                    "github_advisory_"
                    "pypi_exact_package_"
                    "version_range_v1"
                ),
                match_version=(
                    "2.31.0"
                ),
                first_detected_at=now,
                last_evaluated_at=now,
            )
        ),
        epss_score=0.42,
        epss_percentile=0.95,
        cvss_score=9.8,
        cvss_version="3.1",
        cvss_vector=(
            "CVSS:3.1/AV:N/AC:L/"
            "PR:N/UI:N/S:U/C:H/I:H/A:H"
        ),
        cvss_source_name=(
            "github_advisory"
        ),
        cvss_source_role=None,
        weaknesses=(
            AlertWeaknessView(
                cwe_id="CWE-79",
                name=(
                    "Cross-site Scripting"
                ),
                description=(
                    "Example CWE description."
                ),
            ),
        ),
    )


def test_get_alert_detail_returns_item(
) -> None:
    organization_id = uuid4()

    detail = _build_detail()

    list_service = Mock(
        spec=ListAlertsService
    )

    detail_service = Mock(
        spec=GetAlertDetailService
    )

    detail_service.get_alert.return_value = (
        detail
    )

    client = _client(
        list_service,
        detail_service,
    )

    response = client.get(
        (
            "/api/v1/alerts/"
            + str(detail.alert_id)
        ),
        headers={
            "X-Organization-Id": str(
                organization_id
            ),
        },
    )

    assert (
        response.status_code
        == 200
    )

    payload = response.json()

    assert (
        payload["alert_id"]
        == str(detail.alert_id)
    )

    assert (
        payload["alert_type"]
        == (
            "new_confirmed_critical_exposure"
        )
    )

    assert (
        payload["status"]
        == "pending"
    )

    assert (
        payload["primary_identifier"]
        == "CVE-2026-9999"
    )

    assert (
        payload["recipient"]["email"]
        == "security@example.test"
    )

    assert (
        payload["machine"]["hostname"]
        == "PC-SECURITY-01"
    )

    assert (
        payload["component"]["name"]
        == "requests"
    )

    assert (
        payload["exposure"][
            "applicability_status"
        ]
        == "confirmed"
    )

    assert (
        payload["exposure"]["priority"]
        == "CRITICAL"
    )

    assert (
        payload["exposure"]["is_kev"]
        is True
    )

    assert (
        payload["epss_score"]
        == 0.42
    )

    assert (
        payload["cvss_score"]
        == 9.8
    )

    assert (
        payload["weaknesses"][0][
            "cwe_id"
        ]
        == "CWE-79"
    )

    assert len(
        payload["identifiers"]
    ) == 2

    (
        detail_service
        .get_alert
        .assert_called_once_with(
            organization_id=(
                organization_id
            ),
            alert_id=(
                detail.alert_id
            ),
        )
    )


def test_get_alert_detail_returns_404(
) -> None:
    organization_id = uuid4()
    alert_id = uuid4()

    list_service = Mock(
        spec=ListAlertsService
    )

    detail_service = Mock(
        spec=GetAlertDetailService
    )

    detail_service.get_alert.return_value = (
        None
    )

    client = _client(
        list_service,
        detail_service,
    )

    response = client.get(
        (
            "/api/v1/alerts/"
            + str(alert_id)
        ),
        headers={
            "X-Organization-Id": str(
                organization_id
            ),
        },
    )

    assert (
        response.status_code
        == 404
    )

    assert response.json() == {
        "detail": (
            "Alert not found"
        )
    }


def test_get_alert_detail_requires_header(
) -> None:
    list_service = Mock(
        spec=ListAlertsService
    )

    detail_service = Mock(
        spec=GetAlertDetailService
    )

    client = _client(
        list_service,
        detail_service,
    )

    response = client.get(
        (
            "/api/v1/alerts/"
            + str(uuid4())
        )
    )

    assert (
        response.status_code
        == 422
    )


def test_get_alert_detail_maps_repository_error(
) -> None:
    list_service = Mock(
        spec=ListAlertsService
    )

    detail_service = Mock(
        spec=GetAlertDetailService
    )

    detail_service.get_alert.side_effect = (
        AlertReadRepositoryError(
            "database unavailable"
        )
    )

    client = _client(
        list_service,
        detail_service,
    )

    response = client.get(
        (
            "/api/v1/alerts/"
            + str(uuid4())
        ),
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