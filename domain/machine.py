from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from domain._asset_validation import (
    normalize_datetime_utc,
    normalize_required_text,
    validate_uuid,
)


@dataclass(
    frozen=True,
    slots=True,
)
class Machine:
    id: UUID
    organization_id: UUID
    machine_uid: UUID
    hostname: str
    os_name: str
    os_version: str
    architecture: str
    last_inventory_at: datetime | None
    created_at: datetime
    updated_at: datetime

    def __post_init__(self) -> None:
        created_at = normalize_datetime_utc(
            self.created_at,
            field_name="created_at",
        )
        updated_at = normalize_datetime_utc(
            self.updated_at,
            field_name="updated_at",
        )

        if updated_at < created_at:
            raise ValueError(
                "updated_at must not be before created_at"
            )

        last_inventory_at = (
            None
            if self.last_inventory_at is None
            else normalize_datetime_utc(
                self.last_inventory_at,
                field_name="last_inventory_at",
            )
        )

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
            "organization_id",
            validate_uuid(
                self.organization_id,
                field_name="organization_id",
            ),
        )
        object.__setattr__(
            self,
            "machine_uid",
            validate_uuid(
                self.machine_uid,
                field_name="machine_uid",
            ),
        )
        object.__setattr__(
            self,
            "hostname",
            normalize_required_text(
                self.hostname,
                field_name="hostname",
            ),
        )
        object.__setattr__(
            self,
            "os_name",
            normalize_required_text(
                self.os_name,
                field_name="os_name",
            ),
        )
        object.__setattr__(
            self,
            "os_version",
            normalize_required_text(
                self.os_version,
                field_name="os_version",
            ),
        )
        object.__setattr__(
            self,
            "architecture",
            normalize_required_text(
                self.architecture,
                field_name="architecture",
                lowercase=True,
            ),
        )
        object.__setattr__(
            self,
            "last_inventory_at",
            last_inventory_at,
        )
        object.__setattr__(
            self,
            "created_at",
            created_at,
        )
        object.__setattr__(
            self,
            "updated_at",
            updated_at,
        )