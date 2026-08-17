from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
from uuid import UUID


@dataclass(
    frozen=True,
    slots=True,
)
class SecurityResponsibleRecipient:
    id: UUID
    email: str
    display_name: str


class SecurityResponsibleReadRepository(
    Protocol
):
    def find_active_by_organization_id(
        self,
        *,
        organization_id: UUID,
    ) -> tuple[
        SecurityResponsibleRecipient,
        ...,
    ]:
        ...