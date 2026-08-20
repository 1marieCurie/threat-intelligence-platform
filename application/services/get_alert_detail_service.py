from __future__ import annotations

from uuid import UUID

from application.models.alert_view import (
    AlertDetail,
)
from application.ports.outbound.alert_read_repository import (
    AlertReadRepository,
)


class GetAlertDetailService:
    def __init__(
        self,
        *,
        repository: AlertReadRepository,
    ) -> None:
        if repository is None:
            raise ValueError(
                "repository must not be None"
            )

        self._repository = repository

    def get_alert(
        self,
        *,
        organization_id: UUID,
        alert_id: UUID,
    ) -> AlertDetail | None:
        if not isinstance(
            organization_id,
            UUID,
        ):
            raise TypeError(
                "organization_id must be UUID"
            )

        if not isinstance(
            alert_id,
            UUID,
        ):
            raise TypeError(
                "alert_id must be UUID"
            )

        return (
            self._repository
            .get_alert_detail(
                organization_id=(
                    organization_id
                ),
                alert_id=alert_id,
            )
        )