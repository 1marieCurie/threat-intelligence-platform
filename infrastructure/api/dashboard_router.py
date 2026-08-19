from __future__ import annotations

from datetime import datetime
from typing import Literal
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

from application.ports.outbound.dashboard_read_repository import (
    DashboardReadRepositoryError,
)
from application.services.get_dashboard_summary_service import (
    GetDashboardSummaryService,
)


class PriorityDistributionResponse(
    BaseModel
):
    low: int = Field(ge=0)
    medium: int = Field(ge=0)
    high: int = Field(ge=0)
    critical: int = Field(ge=0)


class TopMachineResponse(
    BaseModel
):
    machine_id: UUID
    hostname: str
    exposure_count: int = Field(ge=0)
    critical_count: int = Field(ge=0)
    kev_count: int = Field(ge=0)


class PriorityActionResponse(
    BaseModel
):
    kind: Literal[
        "critical_confirmed",
        "confirmed_kev",
        "notification_attention",
    ]

    title: str

    count: int = Field(
        ge=0
    )

    priority: Literal[
        "LOW",
        "MEDIUM",
        "HIGH",
        "CRITICAL",
    ]


class LatestAlertResponse(
    BaseModel
):
    alert_id: UUID
    alert_type: str

    status: Literal[
        "pending",
        "sent",
        "failed",
    ]

    created_at: datetime
    sent_at: datetime | None

    machine_id: UUID
    hostname: str

    priority: (
        Literal[
            "LOW",
            "MEDIUM",
            "HIGH",
            "CRITICAL",
        ]
        | None
    )


class DashboardResponse(
    BaseModel
):
    machine_count: int = Field(
        ge=0
    )

    component_count: int = Field(
        ge=0
    )

    confirmed_exposure_count: int = (
        Field(
            ge=0
        )
    )

    potential_exposure_count: int = (
        Field(
            ge=0
        )
    )

    critical_exposure_count: int = (
        Field(
            ge=0
        )
    )

    kev_exposure_count: int = (
        Field(
            ge=0
        )
    )

    pending_alert_count: int = Field(
        ge=0
    )

    failed_alert_count: int = Field(
        ge=0
    )

    priority_distribution: (
        PriorityDistributionResponse
    )

    top_machines: list[
        TopMachineResponse
    ]

    priority_actions: list[
        PriorityActionResponse
    ]

    latest_alerts: list[
        LatestAlertResponse
    ]


def create_dashboard_router(
    *,
    service: GetDashboardSummaryService,
) -> APIRouter:
    if service is None:
        raise ValueError(
            "service must not be None"
        )

    router = APIRouter(
        prefix="/api/v1",
        tags=["dashboard"],
    )

    @router.get(
        "/dashboard",
        response_model=DashboardResponse,
        status_code=status.HTTP_200_OK,
    )
    def get_dashboard(
        organization_id: UUID = Header(
            alias="X-Organization-Id"
        ),
    ) -> DashboardResponse:
        try:
            summary = (
                service.get_summary(
                    organization_id=(
                        organization_id
                    )
                )
            )

        except DashboardReadRepositoryError as error:
            raise HTTPException(
                status_code=(
                    status
                    .HTTP_503_SERVICE_UNAVAILABLE
                ),
                detail=(
                    "Dashboard service is "
                    "temporarily unavailable"
                ),
            ) from error

        return DashboardResponse(
            machine_count=(
                summary.machine_count
            ),
            component_count=(
                summary.component_count
            ),
            confirmed_exposure_count=(
                summary
                .confirmed_exposure_count
            ),
            potential_exposure_count=(
                summary
                .potential_exposure_count
            ),
            critical_exposure_count=(
                summary
                .critical_exposure_count
            ),
            kev_exposure_count=(
                summary.kev_exposure_count
            ),
            pending_alert_count=(
                summary.pending_alert_count
            ),
            failed_alert_count=(
                summary.failed_alert_count
            ),
            priority_distribution=(
                PriorityDistributionResponse(
                    low=(
                        summary
                        .priority_distribution
                        .low
                    ),
                    medium=(
                        summary
                        .priority_distribution
                        .medium
                    ),
                    high=(
                        summary
                        .priority_distribution
                        .high
                    ),
                    critical=(
                        summary
                        .priority_distribution
                        .critical
                    ),
                )
            ),
            top_machines=[
                TopMachineResponse(
                    machine_id=(
                        machine.machine_id
                    ),
                    hostname=(
                        machine.hostname
                    ),
                    exposure_count=(
                        machine
                        .exposure_count
                    ),
                    critical_count=(
                        machine
                        .critical_count
                    ),
                    kev_count=(
                        machine.kev_count
                    ),
                )
                for machine
                in summary.top_machines
            ],
            priority_actions=[
                PriorityActionResponse(
                    kind=action.kind,
                    title=action.title,
                    count=action.count,
                    priority=(
                        action.priority
                    ),
                )
                for action
                in summary.priority_actions
            ],
            latest_alerts=[
                LatestAlertResponse(
                    alert_id=(
                        alert.alert_id
                    ),
                    alert_type=(
                        alert.alert_type
                    ),
                    status=(
                        alert.status
                    ),
                    created_at=(
                        alert.created_at
                    ),
                    sent_at=(
                        alert.sent_at
                    ),
                    machine_id=(
                        alert.machine_id
                    ),
                    hostname=(
                        alert.hostname
                    ),
                    priority=(
                        alert.priority
                    ),
                )
                for alert
                in summary.latest_alerts
            ],
        )

    return router