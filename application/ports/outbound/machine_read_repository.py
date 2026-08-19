from __future__ import annotations

from typing import Protocol
from uuid import UUID

from application.models.machine_view import (
    MachineDetail,
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

    def get_machine_detail(
        self,
        *,
        organization_id: UUID,
        machine_id: UUID,
    ) -> MachineDetail | None:
        ...