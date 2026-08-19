from __future__ import annotations

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


def create_vulnerabilities_router(
    *,
    service: ListVulnerabilitiesService,
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
                    for item in items
                ]
            )
        )

    return router