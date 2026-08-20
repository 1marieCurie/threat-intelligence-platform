from __future__ import annotations

from typing import Protocol
from uuid import UUID

from application.models.alert_view import (
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