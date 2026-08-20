from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import (
    APIRouter,
    Body,
    Header,
    HTTPException,
    status,
)
from pydantic import BaseModel

from application.models.machine_inventory_v1 import (
    MachineInventoryV1,
)
from application.ports.outbound.asset_inventory_repository import (
    AssetInventoryConflictError,
    AssetInventoryRepositoryError,
)
from application.services.import_machine_inventory_service import (
    DuplicateInventoryComponentError,
    ImportMachineInventoryResult,
    ImportMachineInventoryService,
    MachineInventoryTimestampConflictError,
    OrganizationInactiveError,
    OrganizationNotFoundError,
    StaleMachineInventoryError,
)


class InventoryImportResponse(
    BaseModel
):
    machine_id: str
    inventory_id: str
    status: str
    machine_created: bool
    inserted_components: int
    updated_components: int
    deleted_components: int
    component_count: int


def create_inventory_imports_router(
    *,
    import_service: ImportMachineInventoryService,
) -> APIRouter:
    if import_service is None:
        raise ValueError(
            "import_service must not be None"
        )

    router = APIRouter(
        prefix="/api/v1",
        tags=["inventory-imports"],
    )

    @router.post(
        "/inventory-imports",
        response_model=InventoryImportResponse,
        status_code=status.HTTP_200_OK,
    )
    def import_inventory(
        payload: dict[
            str,
            Any,
        ] = Body(...),
        organization_id: UUID = Header(
            alias="X-Organization-Id"
        ),
    ) -> InventoryImportResponse:
        inventory = _parse_inventory(
            payload
        )

        try:
            result = (
                import_service.import_inventory(
                    organization_id=(
                        organization_id
                    ),
                    inventory_payload=inventory,
                )
            )

        except (
            OrganizationNotFoundError,
            OrganizationInactiveError,
        ) as error:
            raise HTTPException(
                status_code=(
                    status.HTTP_403_FORBIDDEN
                ),
                detail=(
                    "Organization is not "
                    "authorized for inventory import"
                ),
            ) from error

        except (
            StaleMachineInventoryError,
            MachineInventoryTimestampConflictError,
            AssetInventoryConflictError,
        ) as error:
            raise HTTPException(
                status_code=(
                    status.HTTP_409_CONFLICT
                ),
                detail=str(
                    error
                ),
            ) from error

        except DuplicateInventoryComponentError as error:
            raise HTTPException(
                status_code=(
                    status.HTTP_422_UNPROCESSABLE_CONTENT
                ),
                detail=str(
                    error
                ),
            ) from error

        except AssetInventoryRepositoryError as error:
            raise HTTPException(
                status_code=(
                    status.HTTP_503_SERVICE_UNAVAILABLE
                ),
                detail=(
                    "Inventory persistence "
                    "is temporarily unavailable"
                ),
            ) from error

        return _to_response(
            result
        )

    return router


def _parse_inventory(
    payload: dict[
        str,
        Any,
    ],
) -> MachineInventoryV1:
    try:
        return (
            MachineInventoryV1.from_mapping(
                payload
            )
        )

    except (
        TypeError,
        ValueError,
    ) as error:
        raise HTTPException(
            status_code=(
                status.HTTP_422_UNPROCESSABLE_CONTENT
            ),
            detail=str(
                error
            ),
        ) from error


def _to_response(
    result: ImportMachineInventoryResult,
) -> InventoryImportResponse:
    return InventoryImportResponse(
        machine_id=str(
            result.machine_id
        ),
        inventory_id=str(
            result.inventory_id
        ),
        status=result.status,
        machine_created=(
            result.machine_created
        ),
        inserted_components=(
            result.inserted_components
        ),
        updated_components=(
            result.updated_components
        ),
        deleted_components=(
            result.deleted_components
        ),
        component_count=(
            result.component_count
        ),
    )