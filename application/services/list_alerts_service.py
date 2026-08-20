from __future__ import annotations

from uuid import UUID

from application.models.alert_view import (
    AlertSummary,
)
from application.ports.outbound.alert_read_repository import (
    AlertReadRepository,
)


class ListAlertsService:
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

    def list_alerts(
        self,
        *,
        organization_id: UUID,
    ) -> tuple[
        AlertSummary,
        ...,
    ]:
        if not isinstance(
            organization_id,
            UUID,
        ):
            raise TypeError(
                "organization_id must be UUID"
            )

        return (
            self._repository
            .list_alerts(
                organization_id=(
                    organization_id
                )
            )
        )