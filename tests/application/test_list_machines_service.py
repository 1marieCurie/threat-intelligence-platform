from __future__ import annotations

from uuid import UUID, uuid4

from application.models.machine_view import (
    MachineDetail,
    MachineSummary,
)
from application.services.list_machines_service import (
    ListMachinesService,
)


class FakeMachineRepository:
    def __init__(self) -> None:
        self.organization_id: UUID | None = None

    def list_machines(
        self,
        *,
        organization_id: UUID,
    ) -> tuple[
        MachineSummary,
        ...,
    ]:
        self.organization_id = (
            organization_id
        )

        return ()

    def get_machine_detail(
        self,
        *,
        organization_id: UUID,
        machine_id: UUID,
    ) -> MachineDetail | None:
        del organization_id
        del machine_id

        return None


def test_delegates_with_organization_scope(
) -> None:
    organization_id = uuid4()

    repository = (
        FakeMachineRepository()
    )

    service = (
        ListMachinesService(
            repository=repository
        )
    )

    result = service.list_machines(
        organization_id=(
            organization_id
        )
    )

    assert result == ()

    assert (
        repository.organization_id
        == organization_id
    )