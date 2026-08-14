from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from domain._asset_validation import (
    normalize_datetime_utc,
    normalize_required_text,
    validate_bool,
    validate_uuid,
)


@dataclass(
    frozen=True,
    slots=True,
)
class Organization:
    id: UUID
    name: str
    is_active: bool
    created_at: datetime

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "id",
            validate_uuid(
                self.id,
                field_name="id",
            ),
        )
        object.__setattr__(
            self,
            "name",
            normalize_required_text(
                self.name,
                field_name="name",
            ),
        )
        object.__setattr__(
            self,
            "is_active",
            validate_bool(
                self.is_active,
                field_name="is_active",
            ),
        )
        object.__setattr__(
            self,
            "created_at",
            normalize_datetime_utc(
                self.created_at,
                field_name="created_at",
            ),
        )