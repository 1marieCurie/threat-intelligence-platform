from __future__ import annotations

from typing import Protocol
from uuid import UUID

from application.models.software_view import (
    SoftwareSummary,
)


class SoftwareReadRepositoryError(
    RuntimeError
):
    pass


class SoftwareReadRepository(
    Protocol
):
    def list_software(
        self,
        *,
        organization_id: UUID,
    ) -> tuple[
        SoftwareSummary,
        ...,
    ]:
        ...