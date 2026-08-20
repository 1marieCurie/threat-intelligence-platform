from __future__ import annotations

from uuid import (
    UUID,
    uuid4,
)

from application.models.alert_view import (
    AlertSummary,
)
from application.services.list_alerts_service import (
    ListAlertsService,
)


class FakeAlertRepository:
    def __init__(self) -> None:
        self.organization_id: (
            UUID | None
        ) = None

    def list_alerts(
        self,
        *,
        organization_id: UUID,
    ) -> tuple[
        AlertSummary,
        ...,
    ]:
        self.organization_id = (
            organization_id
        )

        return ()


def test_delegates_with_organization_scope(
) -> None:
    organization_id = uuid4()

    repository = (
        FakeAlertRepository()
    )

    service = (
        ListAlertsService(
            repository=repository
        )
    )

    result = (
        service.list_alerts(
            organization_id=(
                organization_id
            )
        )
    )

    assert result == ()

    assert (
        repository.organization_id
        == organization_id
    )