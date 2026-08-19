from __future__ import annotations

from uuid import UUID

from application.models.machine_view import (
    MachineSummary,
)
from application.ports.outbound.machine_read_repository import (
    MachineReadRepository,
)


class ListMachinesService:
    def __init__(
        self,
        *,
        repository: MachineReadRepository,
    ) -> None:
        if repository is None:
            raise ValueError(
                "repository must not be None"
            )

        self._repository = repository

    def list_machines(
        self,
        *,
        organization_id: UUID,
    ) -> tuple[
        MachineSummary,
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
            self._repository.list_machines(
                organization_id=(
                    organization_id
                )
            )
        )