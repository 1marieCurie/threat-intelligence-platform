from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from domain._asset_validation import (
    normalize_datetime_utc,
    normalize_required_text,
    validate_non_negative_int,
    validate_uuid,
)


@dataclass(
    frozen=True,
    slots=True,
)
class MachineInventoryState:
    machine_id: UUID
    inventory_id: UUID
    schema_version: str
    collected_at: datetime
    imported_at: datetime
    component_count: int

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "machine_id",
            validate_uuid(
                self.machine_id,
                field_name="machine_id",
            ),
        )
        object.__setattr__(
            self,
            "inventory_id",
            validate_uuid(
                self.inventory_id,
                field_name="inventory_id",
            ),
        )
        object.__setattr__(
            self,
            "schema_version",
            normalize_required_text(
                self.schema_version,
                field_name="schema_version",
                lowercase=True,
            ),
        )
        object.__setattr__(
            self,
            "collected_at",
            normalize_datetime_utc(
                self.collected_at,
                field_name="collected_at",
            ),
        )
        object.__setattr__(
            self,
            "imported_at",
            normalize_datetime_utc(
                self.imported_at,
                field_name="imported_at",
            ),
        )
        object.__setattr__(
            self,
            "component_count",
            validate_non_negative_int(
                self.component_count,
                field_name="component_count",
            ),
        )