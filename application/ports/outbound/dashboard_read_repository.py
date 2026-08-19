from __future__ import annotations

from typing import Protocol
from uuid import UUID

from application.models.dashboard import (
    DashboardMetrics,
)


class DashboardReadRepositoryError(
    RuntimeError
):
    pass


class DashboardReadRepository(
    Protocol
):
    def read_metrics(
        self,
        *,
        organization_id: UUID,
    ) -> DashboardMetrics:
        ...