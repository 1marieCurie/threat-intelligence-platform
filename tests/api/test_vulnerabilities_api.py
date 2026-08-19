from __future__ import annotations

from unittest.mock import Mock
from uuid import uuid4

from fastapi.testclient import (
    TestClient,
)

from application.models.vulnerability_view import (
    VulnerabilitySummary,
)
from application.ports.outbound.vulnerability_read_repository import (
    VulnerabilityReadRepositoryError,
)
from application.security.machine_api_key_authenticator import (
    MachineApiKeyAuthenticator,
)
from application.services.import_machine_inventory_service import (
    ImportMachineInventoryService,
)
from application.services.list_vulnerabilities_service import (
    ListVulnerabilitiesService,
)
from infrastructure.api.app import (
    create_app,
)


def _client(
    service: ListVulnerabilitiesService,
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
        vulnerabilities_service=(
            service
        ),
    )

    return TestClient(
        app
    )


def test_list_vulnerabilities_returns_items(
) -> None:
    organization_id = uuid4()
    canonical_id = uuid4()

    service = Mock(
        spec=ListVulnerabilitiesService
    )

    service.list_vulnerabilities.return_value = (
        VulnerabilitySummary(
            canonical_vulnerability_id=(
                canonical_id
            ),
            primary_identifier=(
                "CVE-2026-12345"
            ),
            severity="CRITICAL",
            priority="CRITICAL",
            is_kev=True,
            epss_score=0.91,
            epss_percentile=0.99,
            cvss_score=9.8,
            cvss_version="3.1",
            cwe_ids=(
                "CWE-79",
            ),
            machine_count=2,
            component_count=3,
            confirmed_exposure_count=2,
            potential_exposure_count=1,
        ),
    )

    client = _client(
        service
    )

    response = client.get(
        "/api/v1/vulnerabilities",
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
        item[
            "canonical_vulnerability_id"
        ]
        == str(
            canonical_id
        )
    )

    assert (
        item["primary_identifier"]
        == "CVE-2026-12345"
    )

    assert (
        item["severity"]
        == "CRITICAL"
    )

    assert (
        item["priority"]
        == "CRITICAL"
    )

    assert (
        item["is_kev"]
        is True
    )

    assert (
        item["cvss_score"]
        == 9.8
    )

    assert (
        item["cwe_ids"]
        == [
            "CWE-79",
        ]
    )

    (
        service
        .list_vulnerabilities
        .assert_called_once_with(
            organization_id=(
                organization_id
            )
        )
    )


def test_list_vulnerabilities_requires_header(
) -> None:
    service = Mock(
        spec=ListVulnerabilitiesService
    )

    client = _client(
        service
    )

    response = client.get(
        "/api/v1/vulnerabilities"
    )

    assert response.status_code == 422


def test_list_vulnerabilities_maps_repository_error(
) -> None:
    service = Mock(
        spec=ListVulnerabilitiesService
    )

    service.list_vulnerabilities.side_effect = (
        VulnerabilityReadRepositoryError(
            "database unavailable"
        )
    )

    client = _client(
        service
    )

    response = client.get(
        "/api/v1/vulnerabilities",
        headers={
            "X-Organization-Id": str(
                uuid4()
            ),
        },
    )

    assert response.status_code == 503

    assert response.json() == {
        "detail": (
            "Vulnerability service is "
            "temporarily unavailable"
        )
    }