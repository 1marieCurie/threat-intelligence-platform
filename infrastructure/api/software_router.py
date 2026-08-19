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

from application.ports.outbound.software_read_repository import (
    SoftwareReadRepositoryError,
)
from application.services.list_software_service import (
    ListSoftwareService,
)


class SoftwareSummaryResponse(
    BaseModel
):
    component_type: str

    name: str

    version: str | None

    vendor: str | None
    ecosystem: str | None

    machine_count: int
    exposure_count: int


class SoftwareListResponse(
    BaseModel
):
    items: list[
        SoftwareSummaryResponse
    ]


def create_software_router(
    *,
    service: ListSoftwareService,
) -> APIRouter:
    if service is None:
        raise ValueError(
            "service must not be None"
        )

    router = APIRouter(
        prefix="/api/v1",
        tags=["software"],
    )

    @router.get(
        "/software",
        response_model=SoftwareListResponse,
        status_code=status.HTTP_200_OK,
    )
    def list_software(
        organization_id: UUID = Header(
            alias="X-Organization-Id"
        ),
    ) -> SoftwareListResponse:
        try:
            items = (
                service.list_software(
                    organization_id=(
                        organization_id
                    )
                )
            )

        except (
            SoftwareReadRepositoryError
        ) as error:
            raise HTTPException(
                status_code=(
                    status
                    .HTTP_503_SERVICE_UNAVAILABLE
                ),
                detail=(
                    "Software service is "
                    "temporarily unavailable"
                ),
            ) from error

        return SoftwareListResponse(
            items=[
                SoftwareSummaryResponse(
                    component_type=(
                        item.component_type
                    ),
                    name=item.name,
                    version=item.version,
                    vendor=item.vendor,
                    ecosystem=item.ecosystem,
                    machine_count=(
                        item.machine_count
                    ),
                    exposure_count=(
                        item.exposure_count
                    ),
                )
                for item in items
            ]
        )

    return router