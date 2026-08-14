from __future__ import annotations

from typing import Any

from fastapi import (
    APIRouter,
    Body,
    Depends,
    HTTPException,
    status,
)
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
)
from pydantic import BaseModel

from application.models.machine_inventory_v1 import (
    MachineInventoryV1,
)
from application.ports.outbound.asset_inventory_repository import (
    AssetInventoryConflictError,
    AssetInventoryRepositoryError,
)
from application.security.machine_api_key_authenticator import (
    MachineApiKeyAuthenticator,
    MachinePrincipal,
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


_bearer_scheme = HTTPBearer(
    auto_error=False
)


def create_inventory_router(
    *,
    import_service: (
        ImportMachineInventoryService
    ),
    authenticator: (
        MachineApiKeyAuthenticator
    ),
) -> APIRouter:
    if import_service is None:
        raise ValueError(
            "import_service must not be None"
        )

    if authenticator is None:
        raise ValueError(
            "authenticator must not be None"
        )

    router = APIRouter(
        prefix="/api/v1",
        tags=["inventories"],
    )

    def authenticate_machine(
        credentials: (
            HTTPAuthorizationCredentials | None
        ) = Depends(_bearer_scheme),
    ) -> MachinePrincipal:
        if credentials is None:
            raise _unauthorized()

        if (
            credentials.scheme.lower()
            != "bearer"
        ):
            raise _unauthorized()

        principal = (
            authenticator.authenticate(
                credentials.credentials
            )
        )

        if principal is None:
            raise _unauthorized()

        return principal

    @router.post(
        "/inventories",
        response_model=InventoryImportResponse,
        status_code=status.HTTP_200_OK,
    )
    def import_inventory(
        payload: dict[str, Any] = Body(...),
        principal: MachinePrincipal = Depends(
            authenticate_machine
        ),
    ) -> InventoryImportResponse:
        inventory = _parse_inventory(
            payload
        )

        # Le credential serveur fixe l'identité machine.
        # Le payload n'a pas le droit d'en choisir une autre.
        if (
            inventory.machine.machine_uid
            != principal.machine_uid
        ):
            raise HTTPException(
                status_code=(
                    status.HTTP_403_FORBIDDEN
                ),
                detail=(
                    "Machine credential does not "
                    "match inventory machine_uid"
                ),
            )

        try:
            result = (
                import_service.import_inventory(
                    organization_id=(
                        principal.organization_id
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
                    "Machine credential is not "
                    "authorized for an active "
                    "organization"
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
                detail=str(error),
            ) from error

        except (
            DuplicateInventoryComponentError
        ) as error:
            raise HTTPException(
                status_code=(
                    status.HTTP_422_UNPROCESSABLE_CONTENT
                ),
                detail=str(error),
            ) from error

        except (
            AssetInventoryRepositoryError
        ) as error:
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
    payload: dict[str, Any],
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
            detail=str(error),
        ) from error


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=(
            status.HTTP_401_UNAUTHORIZED
        ),
        detail=(
            "Valid machine API key required"
        ),
        headers={
            "WWW-Authenticate": "Bearer",
        },
    )


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