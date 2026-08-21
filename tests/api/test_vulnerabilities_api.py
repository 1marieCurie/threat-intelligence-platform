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

from application.models.vulnerability_view import (
    VulnerabilityComponentView,
    VulnerabilityDetail,
    VulnerabilityExposureView,
    VulnerabilityIdentifierView,
    VulnerabilityMachineView,
    VulnerabilitySummary,
    VulnerabilityWeaknessView,
)
from application.ports.outbound.vulnerability_read_repository import (
    VulnerabilityReadRepositoryError,
)
from application.security.machine_api_key_authenticator import (
    MachineApiKeyAuthenticator,
)
from application.services.get_vulnerability_detail_service import (
    GetVulnerabilityDetailService,
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


NOW = datetime(
    2026,
    8,
    20,
    17,
    0,
    tzinfo=UTC,
)


def _client(
    service: ListVulnerabilitiesService,
    detail_service: (
        GetVulnerabilityDetailService
        | None
    ) = None,
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
        vulnerability_detail_service=(
            detail_service
        ),
    )

    return TestClient(
        app
    )


def _detail(
    *,
    canonical_id: UUID,
    machine_id: UUID,
    component_id: UUID,
) -> VulnerabilityDetail:
    return VulnerabilityDetail(
        canonical_vulnerability_id=(
            canonical_id
        ),
        primary_identifier=(
            "CVE-2026-12345"
        ),
        identifiers=(
            VulnerabilityIdentifierView(
                namespace="CVE",
                value="CVE-2026-12345",
                is_primary=True,
            ),
            VulnerabilityIdentifierView(
                namespace="GHSA",
                value=(
                    "GHSA-AAAA-BBBB-CCCC"
                ),
                is_primary=False,
            ),
        ),
        severity="CRITICAL",
        priority="CRITICAL",
        is_kev=True,
        epss_score=0.91,
        epss_percentile=0.99,
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
            VulnerabilityWeaknessView(
                cwe_id="CWE-79",
                name=(
                    "Cross-site Scripting"
                ),
                description=(
                    "Improper neutralization "
                    "of input in web output."
                ),
            ),
        ),
        machines=(
            VulnerabilityMachineView(
                machine_id=machine_id,
                hostname="DESKTOP-TEST",
                os_name="Windows 11 Pro",
                os_version="25H2",
                architecture="x86_64",
            ),
        ),
        components=(
            VulnerabilityComponentView(
                component_id=component_id,
                machine_id=machine_id,
                component_type="package",
                name="example-package",
                version="1.2.3",
                vendor=None,
                ecosystem="pypi",
                scope="global",
            ),
        ),
        exposures=(
            VulnerabilityExposureView(
                exposure_id=uuid4(),
                machine_id=machine_id,
                component_id=component_id,
                applicability_status=(
                    "confirmed"
                ),
                severity="CRITICAL",
                priority="CRITICAL",
                is_kev=True,
                match_rule=(
                    "github_advisory_pypi_"
                    "exact_package_"
                    "version_range_v1"
                ),
                match_version="1.2.3",
                first_detected_at=NOW,
                last_evaluated_at=NOW,
            ),
        ),
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


def test_get_vulnerability_returns_detail(
) -> None:
    organization_id = uuid4()
    canonical_id = uuid4()
    machine_id = uuid4()
    component_id = uuid4()

    list_service = Mock(
        spec=ListVulnerabilitiesService
    )

    detail_service = Mock(
        spec=GetVulnerabilityDetailService
    )

    (
        detail_service
        .get_vulnerability
        .return_value
    ) = _detail(
        canonical_id=canonical_id,
        machine_id=machine_id,
        component_id=component_id,
    )

    client = _client(
        list_service,
        detail_service,
    )

    response = client.get(
        (
            "/api/v1/vulnerabilities/"
            f"{canonical_id}"
        ),
        headers={
            "X-Organization-Id": str(
                organization_id
            ),
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert (
        payload[
            "canonical_vulnerability_id"
        ]
        == str(
            canonical_id
        )
    )

    assert (
        payload["primary_identifier"]
        == "CVE-2026-12345"
    )

    assert (
        payload["severity"]
        == "CRITICAL"
    )

    assert (
        payload["priority"]
        == "CRITICAL"
    )

    assert (
        payload["is_kev"]
        is True
    )

    assert (
        payload["epss_score"]
        == 0.91
    )

    assert (
        payload["cvss_score"]
        == 9.8
    )

    assert (
        payload["cvss_version"]
        == "3.1"
    )

    assert len(
        payload["identifiers"]
    ) == 2

    assert (
        payload["identifiers"][0]
        ["value"]
        == "CVE-2026-12345"
    )

    assert len(
        payload["weaknesses"]
    ) == 1

    assert (
        payload["weaknesses"][0]
        ["cwe_id"]
        == "CWE-79"
    )

    assert len(
        payload["machines"]
    ) == 1

    assert (
        payload["machines"][0]
        ["machine_id"]
        == str(
            machine_id
        )
    )

    assert len(
        payload["components"]
    ) == 1

    assert (
        payload["components"][0]
        ["component_id"]
        == str(
            component_id
        )
    )

    assert len(
        payload["exposures"]
    ) == 1

    assert (
        payload["exposures"][0]
        ["applicability_status"]
        == "confirmed"
    )

    (
        detail_service
        .get_vulnerability
        .assert_called_once_with(
            organization_id=(
                organization_id
            ),
            canonical_vulnerability_id=(
                canonical_id
            ),
        )
    )


def test_get_vulnerability_returns_404_when_not_visible(
) -> None:
    list_service = Mock(
        spec=ListVulnerabilitiesService
    )

    detail_service = Mock(
        spec=GetVulnerabilityDetailService
    )

    (
        detail_service
        .get_vulnerability
        .return_value
    ) = None

    client = _client(
        list_service,
        detail_service,
    )

    response = client.get(
        (
            "/api/v1/vulnerabilities/"
            f"{uuid4()}"
        ),
        headers={
            "X-Organization-Id": str(
                uuid4()
            ),
        },
    )

    assert (
        response.status_code
        == 404
    )

    assert response.json() == {
        "detail": (
            "Vulnerability not found"
        )
    }


def test_get_vulnerability_requires_header(
) -> None:
    list_service = Mock(
        spec=ListVulnerabilitiesService
    )

    detail_service = Mock(
        spec=GetVulnerabilityDetailService
    )

    client = _client(
        list_service,
        detail_service,
    )

    response = client.get(
        (
            "/api/v1/vulnerabilities/"
            f"{uuid4()}"
        )
    )

    assert response.status_code == 422


def test_get_vulnerability_maps_repository_error(
) -> None:
    list_service = Mock(
        spec=ListVulnerabilitiesService
    )

    detail_service = Mock(
        spec=GetVulnerabilityDetailService
    )

    (
        detail_service
        .get_vulnerability
        .side_effect
    ) = (
        VulnerabilityReadRepositoryError(
            "database unavailable"
        )
    )

    client = _client(
        list_service,
        detail_service,
    )

    response = client.get(
        (
            "/api/v1/vulnerabilities/"
            f"{uuid4()}"
        ),
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