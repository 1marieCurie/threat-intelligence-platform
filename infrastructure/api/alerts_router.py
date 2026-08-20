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

from application.ports.outbound.alert_read_repository import (
    AlertReadRepositoryError,
)
from application.services.list_alerts_service import (
    ListAlertsService,
)


class AlertSummaryResponse(
    BaseModel
):
    alert_id: UUID

    alert_type: str
    status: str

    created_at: datetime
    sent_at: datetime | None

    machine_id: UUID
    machine_hostname: str

    canonical_vulnerability_id: UUID
    primary_identifier: str | None

    component_name: str | None
    component_version: str | None

    current_priority: str | None
    is_kev: bool | None


class AlertListResponse(
    BaseModel
):
    items: list[
        AlertSummaryResponse
    ]


def create_alerts_router(
    *,
    service: ListAlertsService,
) -> APIRouter:
    if service is None:
        raise ValueError(
            "service must not be None"
        )

    router = APIRouter(
        prefix="/api/v1",
        tags=["alerts"],
    )

    @router.get(
        "/alerts",
        response_model=(
            AlertListResponse
        ),
        status_code=status.HTTP_200_OK,
    )
    def list_alerts(
        organization_id: UUID = Header(
            alias="X-Organization-Id"
        ),
    ) -> AlertListResponse:
        try:
            items = (
                service
                .list_alerts(
                    organization_id=(
                        organization_id
                    )
                )
            )

        except AlertReadRepositoryError as error:
            raise HTTPException(
                status_code=(
                    status
                    .HTTP_503_SERVICE_UNAVAILABLE
                ),
                detail=(
                    "Alert service is "
                    "temporarily unavailable"
                ),
            ) from error

        return AlertListResponse(
            items=[
                AlertSummaryResponse(
                    alert_id=(
                        item.alert_id
                    ),
                    alert_type=(
                        item.alert_type
                    ),
                    status=(
                        item.status
                    ),
                    created_at=(
                        item.created_at
                    ),
                    sent_at=(
                        item.sent_at
                    ),
                    machine_id=(
                        item.machine_id
                    ),
                    machine_hostname=(
                        item.machine_hostname
                    ),
                    canonical_vulnerability_id=(
                        item
                        .canonical_vulnerability_id
                    ),
                    primary_identifier=(
                        item.primary_identifier
                    ),
                    component_name=(
                        item.component_name
                    ),
                    component_version=(
                        item.component_version
                    ),
                    current_priority=(
                        item.current_priority
                    ),
                    is_kev=(
                        item.is_kev
                    ),
                )
                for item in items
            ]
        )

    return router