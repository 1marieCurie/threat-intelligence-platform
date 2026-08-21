from __future__ import annotations

from uuid import UUID, uuid4

from application.models.machine_view import (
    MachineDetail,
    MachineSummary,
)
from application.services.get_machine_detail_service import (
    GetMachineDetailService,
)


class FakeMachineRepository:
    def __init__(self) -> None:
        self.organization_id: UUID | None = None
        self.machine_id: UUID | None = None

    def list_machines(
        self,
        *,
        organization_id: UUID,
    ) -> tuple[
        MachineSummary,
        ...,
    ]:
        del organization_id

        return ()

    def get_machine_detail(
        self,
        *,
        organization_id: UUID,
        machine_id: UUID,
    ) -> MachineDetail | None:
        self.organization_id = (
            organization_id
        )

        self.machine_id = (
            machine_id
        )

        return None


def test_delegates_with_tenant_and_machine_scope(
) -> None:
    organization_id = uuid4()
    machine_id = uuid4()

    repository = (
        FakeMachineRepository()
    )

    service = (
        GetMachineDetailService(
            repository=repository
        )
    )

    result = service.get_machine(
        organization_id=(
            organization_id
        ),
        machine_id=(
            machine_id
        ),
    )

    assert result is None

    assert (
        repository.organization_id
        == organization_id
    )

    assert (
        repository.machine_id
        == machine_id
    )