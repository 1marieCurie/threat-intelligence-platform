from __future__ import annotations

from typing import Protocol
from uuid import UUID

from application.models.alert_view import (
    AlertDetail,
    AlertSummary,
)


class AlertReadRepositoryError(
    RuntimeError
):
    pass


class AlertReadRepository(
    Protocol
):
    def list_alerts(
        self,
        *,
        organization_id: UUID,
    ) -> tuple[
        AlertSummary,
        ...,
    ]:
        ...

    def get_alert_detail(
        self,
        *,
        organization_id: UUID,
        alert_id: UUID,
    ) -> AlertDetail | None:
        ...