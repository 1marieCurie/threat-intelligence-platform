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
from application.services.get_machine_detail_service import (
    GetMachineDetailService,
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
    
class MachineComponentResponse(
    BaseModel
):
    component_id: UUID
    component_type: str

    name: str
    version: str | None
    vendor: str | None

    ecosystem: str | None
    scope: str | None

    detected_by: str


class MachineExposureResponse(
    BaseModel
):
    exposure_id: UUID
    canonical_vulnerability_id: UUID

    primary_identifier: str | None

    component_id: UUID
    component_name: str
    component_version: str | None

    applicability_status: str

    severity: str | None
    priority: str | None

    is_kev: bool

    match_rule: str
    match_version: str | None


class MachineDetailResponse(
    BaseModel
):
    machine_id: UUID
    machine_uid: UUID

    hostname: str

    os_name: str
    os_version: str
    architecture: str

    last_inventory_at: datetime | None

    components: list[
        MachineComponentResponse
    ]

    exposures: list[
        MachineExposureResponse
    ]


def create_machines_router(
    *,
    list_service: ListMachinesService,
    detail_service: GetMachineDetailService,
) -> APIRouter:
    
    if list_service is None:
        raise ValueError(
            "list_service must not be None"
        )

    if detail_service is None:
        raise ValueError(
            "detail_service must not be None"
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
                list_service.list_machines(
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
    
    @router.get(
        "/machines/{machine_id}",
        response_model=MachineDetailResponse,
        status_code=status.HTTP_200_OK,
    )
    
    def get_machine(
        machine_id: UUID,
        organization_id: UUID = Header(
            alias="X-Organization-Id"
        ),
    ) -> MachineDetailResponse:
        try:
            machine = (
                detail_service.get_machine(
                    organization_id=organization_id,
                    machine_id=machine_id,
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

        if machine is None:
            raise HTTPException(
                status_code=(
                    status.HTTP_404_NOT_FOUND
                ),
                detail="Machine not found",
            )

        return MachineDetailResponse(
            machine_id=machine.machine_id,
            machine_uid=machine.machine_uid,
            hostname=machine.hostname,
            os_name=machine.os_name,
            os_version=machine.os_version,
            architecture=machine.architecture,
            last_inventory_at=(
                machine.last_inventory_at
            ),
            components=[
                MachineComponentResponse(
                    component_id=item.component_id,
                    component_type=item.component_type,
                    name=item.name,
                    version=item.version,
                    vendor=item.vendor,
                    ecosystem=item.ecosystem,
                    scope=item.scope,
                    detected_by=item.detected_by,
                )
                for item in machine.components
            ],
            exposures=[
                MachineExposureResponse(
                    exposure_id=item.exposure_id,
                    canonical_vulnerability_id=(
                        item.canonical_vulnerability_id
                    ),
                    primary_identifier=(
                        item.primary_identifier
                    ),
                    component_id=item.component_id,
                    component_name=item.component_name,
                    component_version=item.component_version,
                    applicability_status=(
                        item.applicability_status
                    ),
                    severity=item.severity,
                    priority=item.priority,
                    is_kev=item.is_kev,
                    match_rule=item.match_rule,
                    match_version=item.match_version,
                )
                for item in machine.exposures
            ],
        )

    return router

