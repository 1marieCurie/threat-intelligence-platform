from __future__ import annotations

from uuid import UUID

from application.models.machine_view import (
    MachineDetail,
)
from application.ports.outbound.machine_read_repository import (
    MachineReadRepository,
)


class GetMachineDetailService:
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

    def get_machine(
        self,
        *,
        organization_id: UUID,
        machine_id: UUID,
    ) -> MachineDetail | None:
        if not isinstance(
            organization_id,
            UUID,
        ):
            raise TypeError(
                "organization_id must be UUID"
            )

        if not isinstance(
            machine_id,
            UUID,
        ):
            raise TypeError(
                "machine_id must be UUID"
            )

        return (
            self._repository.get_machine_detail(
                organization_id=organization_id,
                machine_id=machine_id,
            )
        )