from __future__ import annotations

from uuid import (
    UUID,
    uuid4,
)

from application.models.software_view import (
    SoftwareSummary,
)
from application.services.list_software_service import (
    ListSoftwareService,
)


class FakeSoftwareRepository:
    def __init__(self) -> None:
        self.organization_id: (
            UUID | None
        ) = None

    def list_software(
        self,
        *,
        organization_id: UUID,
    ) -> tuple[
        SoftwareSummary,
        ...,
    ]:
        self.organization_id = (
            organization_id
        )

        return ()


def test_delegates_with_organization_scope(
) -> None:
    organization_id = uuid4()

    repository = (
        FakeSoftwareRepository()
    )

    service = (
        ListSoftwareService(
            repository=repository
        )
    )

    result = service.list_software(
        organization_id=(
            organization_id
        )
    )

    assert result == ()

    assert (
        repository.organization_id
        == organization_id
    )