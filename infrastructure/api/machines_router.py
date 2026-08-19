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
    Field,
)

from application.ports.outbound.machine_read_repository import (
    MachineReadRepositoryError,
)
from application.services.list_machines_service import (
    ListMachinesService,
)


class MachineSummaryResponse(
    BaseModel
):
    machine_id: UUID
    hostname: str

    os_name: str
    os_version: str
    architecture: str

    last_inventory_at: datetime | None

    component_count: int = Field(
        ge=0
    )

    exposure_count: int = Field(
        ge=0
    )

    critical_exposure_count: int = (
        Field(
            ge=0
        )
    )

    kev_exposure_count: int = Field(
        ge=0
    )


class MachineListResponse(
    BaseModel
):
    items: list[
        MachineSummaryResponse
    ]


def create_machines_router(
    *,
    service: ListMachinesService,
) -> APIRouter:
    if service is None:
        raise ValueError(
            "service must not be None"
        )

    router = APIRouter(
        prefix="/api/v1",
        tags=["machines"],
    )

    @router.get(
        "/machines",
        response_model=MachineListResponse,
        status_code=status.HTTP_200_OK,
    )
    def list_machines(
        organization_id: UUID = Header(
            alias="X-Organization-Id"
        ),
    ) -> MachineListResponse:
        try:
            machines = (
                service.list_machines(
                    organization_id=(
                        organization_id
                    )
                )
            )

        except MachineReadRepositoryError as error:
            raise HTTPException(
                status_code=(
                    status
                    .HTTP_503_SERVICE_UNAVAILABLE
                ),
                detail=(
                    "Machine service is "
                    "temporarily unavailable"
                ),
            ) from error

        return MachineListResponse(
            items=[
                MachineSummaryResponse(
                    machine_id=(
                        machine.machine_id
                    ),
                    hostname=(
                        machine.hostname
                    ),
                    os_name=(
                        machine.os_name
                    ),
                    os_version=(
                        machine.os_version
                    ),
                    architecture=(
                        machine.architecture
                    ),
                    last_inventory_at=(
                        machine
                        .last_inventory_at
                    ),
                    component_count=(
                        machine
                        .component_count
                    ),
                    exposure_count=(
                        machine
                        .exposure_count
                    ),
                    critical_exposure_count=(
                        machine
                        .critical_exposure_count
                    ),
                    kev_exposure_count=(
                        machine
                        .kev_exposure_count
                    ),
                )
                for machine
                in machines
            ]
        )

    return router