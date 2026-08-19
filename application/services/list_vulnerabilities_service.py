from __future__ import annotations

from uuid import UUID

from application.models.vulnerability_view import (
    VulnerabilitySummary,
)
from application.ports.outbound.vulnerability_read_repository import (
    VulnerabilityReadRepository,
)


class ListVulnerabilitiesService:
    def __init__(
        self,
        *,
        repository: VulnerabilityReadRepository,
    ) -> None:
        if repository is None:
            raise ValueError(
                "repository must not be None"
            )

        self._repository = repository

    def list_vulnerabilities(
        self,
        *,
        organization_id: UUID,
    ) -> tuple[
        VulnerabilitySummary,
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
            self._repository
            .list_vulnerabilities(
                organization_id=(
                    organization_id
                )
            )
        )