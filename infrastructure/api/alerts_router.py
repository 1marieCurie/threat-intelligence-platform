from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi import (
    APIRouter,
    Header,
    HTTPException,
    status,
)
from pydantic import BaseModel

from application.ports.outbound.alert_read_repository import (
    AlertReadRepositoryError,
)
from application.services.get_alert_detail_service import (
    GetAlertDetailService,
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


class AlertIdentifierResponse(
    BaseModel
):
    namespace: str
    value: str
    is_primary: bool


class AlertWeaknessResponse(
    BaseModel
):
    cwe_id: str
    name: str
    description: str


class AlertRecipientResponse(
    BaseModel
):
    user_id: UUID
    email: str
    display_name: str


class AlertMachineResponse(
    BaseModel
):
    machine_id: UUID

    hostname: str
    os_name: str
    os_version: str
    architecture: str


class AlertComponentResponse(
    BaseModel
):
    component_id: UUID

    component_type: str
    name: str
    version: str | None

    vendor: str | None
    ecosystem: str | None
    scope: str | None


class AlertExposureResponse(
    BaseModel
):
    exposure_id: UUID

    applicability_status: str

    severity: str | None
    priority: str | None

    is_kev: bool

    match_rule: str
    match_version: str | None

    first_detected_at: datetime
    last_evaluated_at: datetime


class AlertDetailResponse(
    BaseModel
):
    alert_id: UUID

    alert_type: str
    status: str

    created_at: datetime
    sent_at: datetime | None

    recipient: AlertRecipientResponse

    machine: AlertMachineResponse

    canonical_vulnerability_id: UUID
    primary_identifier: str | None

    identifiers: list[
        AlertIdentifierResponse
    ]

    component: (
        AlertComponentResponse
        | None
    )

    exposure: (
        AlertExposureResponse
        | None
    )

    epss_score: float | None
    epss_percentile: float | None

    cvss_score: float | None
    cvss_version: str | None
    cvss_vector: str | None

    cvss_source_name: str | None
    cvss_source_role: str | None

    weaknesses: list[
        AlertWeaknessResponse
    ]


def create_alerts_router(
    *,
    service: ListAlertsService,
    detail_service: (
        GetAlertDetailService
        | None
    ) = None,
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

    if detail_service is not None:

        @router.get(
            "/alerts/{alert_id}",
            response_model=(
                AlertDetailResponse
            ),
            status_code=(
                status.HTTP_200_OK
            ),
        )
        def get_alert_detail(
            alert_id: UUID,
            organization_id: UUID = Header(
                alias="X-Organization-Id"
            ),
        ) -> AlertDetailResponse:
            try:
                detail = (
                    detail_service
                    .get_alert(
                        organization_id=(
                            organization_id
                        ),
                        alert_id=alert_id,
                    )
                )

            except (
                AlertReadRepositoryError
            ) as error:
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

            if detail is None:
                raise HTTPException(
                    status_code=(
                        status
                        .HTTP_404_NOT_FOUND
                    ),
                    detail=(
                        "Alert not found"
                    ),
                )

            component_response = (
                None
            )

            if (
                detail.component
                is not None
            ):
                component_response = (
                    AlertComponentResponse(
                        component_id=(
                            detail
                            .component
                            .component_id
                        ),
                        component_type=(
                            detail
                            .component
                            .component_type
                        ),
                        name=(
                            detail
                            .component
                            .name
                        ),
                        version=(
                            detail
                            .component
                            .version
                        ),
                        vendor=(
                            detail
                            .component
                            .vendor
                        ),
                        ecosystem=(
                            detail
                            .component
                            .ecosystem
                        ),
                        scope=(
                            detail
                            .component
                            .scope
                        ),
                    )
                )

            exposure_response = (
                None
            )

            if (
                detail.exposure
                is not None
            ):
                exposure_response = (
                    AlertExposureResponse(
                        exposure_id=(
                            detail
                            .exposure
                            .exposure_id
                        ),
                        applicability_status=(
                            detail
                            .exposure
                            .applicability_status
                        ),
                        severity=(
                            detail
                            .exposure
                            .severity
                        ),
                        priority=(
                            detail
                            .exposure
                            .priority
                        ),
                        is_kev=(
                            detail
                            .exposure
                            .is_kev
                        ),
                        match_rule=(
                            detail
                            .exposure
                            .match_rule
                        ),
                        match_version=(
                            detail
                            .exposure
                            .match_version
                        ),
                        first_detected_at=(
                            detail
                            .exposure
                            .first_detected_at
                        ),
                        last_evaluated_at=(
                            detail
                            .exposure
                            .last_evaluated_at
                        ),
                    )
                )

            return AlertDetailResponse(
                alert_id=(
                    detail.alert_id
                ),
                alert_type=(
                    detail.alert_type
                ),
                status=(
                    detail.status
                ),
                created_at=(
                    detail.created_at
                ),
                sent_at=(
                    detail.sent_at
                ),
                recipient=(
                    AlertRecipientResponse(
                        user_id=(
                            detail
                            .recipient
                            .user_id
                        ),
                        email=(
                            detail
                            .recipient
                            .email
                        ),
                        display_name=(
                            detail
                            .recipient
                            .display_name
                        ),
                    )
                ),
                machine=(
                    AlertMachineResponse(
                        machine_id=(
                            detail
                            .machine
                            .machine_id
                        ),
                        hostname=(
                            detail
                            .machine
                            .hostname
                        ),
                        os_name=(
                            detail
                            .machine
                            .os_name
                        ),
                        os_version=(
                            detail
                            .machine
                            .os_version
                        ),
                        architecture=(
                            detail
                            .machine
                            .architecture
                        ),
                    )
                ),
                canonical_vulnerability_id=(
                    detail
                    .canonical_vulnerability_id
                ),
                primary_identifier=(
                    detail.primary_identifier
                ),
                identifiers=[
                    AlertIdentifierResponse(
                        namespace=(
                            item.namespace
                        ),
                        value=(
                            item.value
                        ),
                        is_primary=(
                            item.is_primary
                        ),
                    )
                    for item
                    in detail.identifiers
                ],
                component=(
                    component_response
                ),
                exposure=(
                    exposure_response
                ),
                epss_score=(
                    detail.epss_score
                ),
                epss_percentile=(
                    detail
                    .epss_percentile
                ),
                cvss_score=(
                    detail.cvss_score
                ),
                cvss_version=(
                    detail.cvss_version
                ),
                cvss_vector=(
                    detail.cvss_vector
                ),
                cvss_source_name=(
                    detail
                    .cvss_source_name
                ),
                cvss_source_role=(
                    detail
                    .cvss_source_role
                ),
                weaknesses=[
                    AlertWeaknessResponse(
                        cwe_id=(
                            item.cwe_id
                        ),
                        name=(
                            item.name
                        ),
                        description=(
                            item.description
                        ),
                    )
                    for item
                    in detail.weaknesses
                ],
            )

    return router