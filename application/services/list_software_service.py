from __future__ import annotations

from uuid import UUID

from application.models.software_view import (
    SoftwareSummary,
)
from application.ports.outbound.software_read_repository import (
    SoftwareReadRepository,
)


class ListSoftwareService:
    def __init__(
        self,
        *,
        repository: SoftwareReadRepository,
    ) -> None:
        if repository is None:
            raise ValueError(
                "repository must not be None"
            )

        self._repository = repository

    def list_software(
        self,
        *,
        organization_id: UUID,
    ) -> tuple[
        SoftwareSummary,
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
            self._repository.list_software(
                organization_id=(
                    organization_id
                )
            )
        )