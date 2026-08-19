from __future__ import annotations

from typing import Protocol
from uuid import UUID

from application.models.machine_view import (
    MachineSummary,
)


class MachineReadRepositoryError(
    RuntimeError
):
    pass


class MachineReadRepository(
    Protocol
):
    def list_machines(
        self,
        *,
        organization_id: UUID,
    ) -> tuple[
        MachineSummary,
        ...,
    ]:
        ...