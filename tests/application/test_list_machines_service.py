from uuid import uuid4

from application.services.list_machines_service import (
    ListMachinesService,
)


class FakeMachineRepository:
    def __init__(self) -> None:
        self.organization_id = None

    def list_machines(
        self,
        *,
        organization_id,
    ):
        self.organization_id = (
            organization_id
        )

        return ()


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
        organization_id=organization_id
    )

    assert result == ()

    assert (
        repository.organization_id
        == organization_id
    )