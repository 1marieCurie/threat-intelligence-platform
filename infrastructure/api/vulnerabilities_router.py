from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import (
    APIRouter,
    Header,
    HTTPException,
    status,
)
from pydantic import (
    BaseModel,
)

from application.ports.outbound.vulnerability_read_repository import (
    VulnerabilityReadRepositoryError,
)
from application.services.get_vulnerability_detail_service import (
    GetVulnerabilityDetailService,
)
from application.services.list_vulnerabilities_service import (
    ListVulnerabilitiesService,
)


class VulnerabilitySummaryResponse(
    BaseModel
):
    canonical_vulnerability_id: UUID

    primary_identifier: str | None

    severity: str | None
    priority: str | None

    is_kev: bool

    epss_score: float | None
    epss_percentile: float | None

    cvss_score: float | None
    cvss_version: str | None

    cwe_ids: list[str]

    machine_count: int
    component_count: int

    confirmed_exposure_count: int
    potential_exposure_count: int


class VulnerabilityListResponse(
    BaseModel
):
    items: list[
        VulnerabilitySummaryResponse
    ]


class VulnerabilityIdentifierResponse(
    BaseModel
):
    namespace: str
    value: str
    is_primary: bool


class VulnerabilityWeaknessResponse(
    BaseModel
):
    cwe_id: str
    name: str
    description: str


class VulnerabilityMachineResponse(
    BaseModel
):
    machine_id: UUID

    hostname: str

    os_name: str
    os_version: str
    architecture: str


class VulnerabilityComponentResponse(
    BaseModel
):
    component_id: UUID
    machine_id: UUID

    component_type: str

    name: str
    version: str | None
    vendor: str | None

    ecosystem: str | None
    scope: str | None


class VulnerabilityExposureResponse(
    BaseModel
):
    exposure_id: UUID

    machine_id: UUID
    component_id: UUID

    applicability_status: str

    severity: str | None
    priority: str | None

    is_kev: bool

    match_rule: str
    match_version: str | None

    first_detected_at: datetime
    last_evaluated_at: datetime


class VulnerabilityDetailResponse(
    BaseModel
):
    canonical_vulnerability_id: UUID

    primary_identifier: str | None

    identifiers: list[
        VulnerabilityIdentifierResponse
    ]

    severity: str | None
    priority: str | None

    is_kev: bool

    epss_score: float | None
    epss_percentile: float | None

    cvss_score: float | None
    cvss_version: str | None
    cvss_vector: str | None
    cvss_source_name: str | None
    cvss_source_role: str | None

    weaknesses: list[
        VulnerabilityWeaknessResponse
    ]

    machines: list[
        VulnerabilityMachineResponse
    ]

    components: list[
        VulnerabilityComponentResponse
    ]

    exposures: list[
        VulnerabilityExposureResponse
    ]


def create_vulnerabilities_router(
    *,
    service: ListVulnerabilitiesService,
    detail_service: (
        GetVulnerabilityDetailService
        | None
    ) = None,
) -> APIRouter:
    if service is None:
        raise ValueError(
            "service must not be None"
        )

    router = APIRouter(
        prefix="/api/v1",
        tags=["vulnerabilities"],
    )

    @router.get(
        "/vulnerabilities",
        response_model=(
            VulnerabilityListResponse
        ),
        status_code=status.HTTP_200_OK,
    )
    def list_vulnerabilities(
        organization_id: UUID = Header(
            alias="X-Organization-Id"
        ),
    ) -> VulnerabilityListResponse:
        try:
            items = (
                service
                .list_vulnerabilities(
                    organization_id=(
                        organization_id
                    )
                )
            )

        except (
            VulnerabilityReadRepositoryError
        ) as error:
            raise HTTPException(
                status_code=(
                    status
                    .HTTP_503_SERVICE_UNAVAILABLE
                ),
                detail=(
                    "Vulnerability service is "
                    "temporarily unavailable"
                ),
            ) from error

        return (
            VulnerabilityListResponse(
                items=[
                    VulnerabilitySummaryResponse(
                        canonical_vulnerability_id=(
                            item
                            .canonical_vulnerability_id
                        ),
                        primary_identifier=(
                            item
                            .primary_identifier
                        ),
                        severity=(
                            item.severity
                        ),
                        priority=(
                            item.priority
                        ),
                        is_kev=(
                            item.is_kev
                        ),
                        epss_score=(
                            item.epss_score
                        ),
                        epss_percentile=(
                            item
                            .epss_percentile
                        ),
                        cvss_score=(
                            item.cvss_score
                        ),
                        cvss_version=(
                            item.cvss_version
                        ),
                        cwe_ids=list(
                            item.cwe_ids
                        ),
                        machine_count=(
                            item.machine_count
                        ),
                        component_count=(
                            item.component_count
                        ),
                        confirmed_exposure_count=(
                            item
                            .confirmed_exposure_count
                        ),
                        potential_exposure_count=(
                            item
                            .potential_exposure_count
                        ),
                    )
                    for item
                    in items
                ]
            )
        )

    if detail_service is not None:

        @router.get(
            (
                "/vulnerabilities/"
                "{canonical_vulnerability_id}"
            ),
            response_model=(
                VulnerabilityDetailResponse
            ),
            status_code=(
                status.HTTP_200_OK
            ),
        )
        def get_vulnerability(
            canonical_vulnerability_id: UUID,
            organization_id: UUID = Header(
                alias="X-Organization-Id"
            ),
        ) -> VulnerabilityDetailResponse:
            try:
                vulnerability = (
                    detail_service
                    .get_vulnerability(
                        organization_id=(
                            organization_id
                        ),
                        canonical_vulnerability_id=(
                            canonical_vulnerability_id
                        ),
                    )
                )

            except (
                VulnerabilityReadRepositoryError
            ) as error:
                raise HTTPException(
                    status_code=(
                        status
                        .HTTP_503_SERVICE_UNAVAILABLE
                    ),
                    detail=(
                        "Vulnerability service "
                        "is temporarily unavailable"
                    ),
                ) from error

            if vulnerability is None:
                raise HTTPException(
                    status_code=(
                        status.HTTP_404_NOT_FOUND
                    ),
                    detail=(
                        "Vulnerability not found"
                    ),
                )

            return VulnerabilityDetailResponse(
                canonical_vulnerability_id=(
                    vulnerability
                    .canonical_vulnerability_id
                ),
                primary_identifier=(
                    vulnerability
                    .primary_identifier
                ),
                identifiers=[
                    VulnerabilityIdentifierResponse(
                        namespace=(
                            item.namespace
                        ),
                        value=item.value,
                        is_primary=(
                            item.is_primary
                        ),
                    )
                    for item
                    in vulnerability.identifiers
                ],
                severity=(
                    vulnerability.severity
                ),
                priority=(
                    vulnerability.priority
                ),
                is_kev=(
                    vulnerability.is_kev
                ),
                epss_score=(
                    vulnerability.epss_score
                ),
                epss_percentile=(
                    vulnerability
                    .epss_percentile
                ),
                cvss_score=(
                    vulnerability.cvss_score
                ),
                cvss_version=(
                    vulnerability.cvss_version
                ),
                cvss_vector=(
                    vulnerability.cvss_vector
                ),
                cvss_source_name=(
                    vulnerability
                    .cvss_source_name
                ),
                cvss_source_role=(
                    vulnerability
                    .cvss_source_role
                ),
                weaknesses=[
                    VulnerabilityWeaknessResponse(
                        cwe_id=item.cwe_id,
                        name=item.name,
                        description=(
                            item.description
                        ),
                    )
                    for item
                    in vulnerability.weaknesses
                ],
                machines=[
                    VulnerabilityMachineResponse(
                        machine_id=(
                            item.machine_id
                        ),
                        hostname=(
                            item.hostname
                        ),
                        os_name=(
                            item.os_name
                        ),
                        os_version=(
                            item.os_version
                        ),
                        architecture=(
                            item.architecture
                        ),
                    )
                    for item
                    in vulnerability.machines
                ],
                components=[
                    VulnerabilityComponentResponse(
                        component_id=(
                            item.component_id
                        ),
                        machine_id=(
                            item.machine_id
                        ),
                        component_type=(
                            item.component_type
                        ),
                        name=item.name,
                        version=item.version,
                        vendor=item.vendor,
                        ecosystem=(
                            item.ecosystem
                        ),
                        scope=item.scope,
                    )
                    for item
                    in vulnerability.components
                ],
                exposures=[
                    VulnerabilityExposureResponse(
                        exposure_id=(
                            item.exposure_id
                        ),
                        machine_id=(
                            item.machine_id
                        ),
                        component_id=(
                            item.component_id
                        ),
                        applicability_status=(
                            item
                            .applicability_status
                        ),
                        severity=(
                            item.severity
                        ),
                        priority=(
                            item.priority
                        ),
                        is_kev=(
                            item.is_kev
                        ),
                        match_rule=(
                            item.match_rule
                        ),
                        match_version=(
                            item.match_version
                        ),
                        first_detected_at=(
                            item
                            .first_detected_at
                        ),
                        last_evaluated_at=(
                            item
                            .last_evaluated_at
                        ),
                    )
                    for item
                    in vulnerability.exposures
                ],
            )

    return router