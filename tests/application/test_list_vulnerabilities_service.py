from __future__ import annotations

from uuid import (
    UUID,
    uuid4,
)

from application.models.vulnerability_view import (
    VulnerabilitySummary,
)
from application.services.list_vulnerabilities_service import (
    ListVulnerabilitiesService,
)


class FakeVulnerabilityRepository:
    def __init__(self) -> None:
        self.organization_id: (
            UUID | None
        ) = None

    def list_vulnerabilities(
        self,
        *,
        organization_id: UUID,
    ) -> tuple[
        VulnerabilitySummary,
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
        FakeVulnerabilityRepository()
    )

    service = (
        ListVulnerabilitiesService(
            repository=repository
        )
    )

    result = (
        service.list_vulnerabilities(
            organization_id=(
                organization_id
            )
        )
    )

    assert result == ()

    assert (
        repository.organization_id
        == organization_id
    )