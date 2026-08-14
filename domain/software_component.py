from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from domain._asset_validation import (
    normalize_choice,
    normalize_datetime_utc,
    normalize_optional_text,
    normalize_required_text,
    validate_uuid,
)


SUPPORTED_COMPONENT_TYPES = frozenset(
    {
        "application",
        "package",
    }
)


@dataclass(frozen=True, slots=True)
class SoftwareComponent:
    id: UUID
    machine_id: UUID
    component_type: str
    name: str
    normalized_name: str | None
    version: str | None
    vendor: str | None
    normalized_vendor: str | None
    ecosystem: str | None
    external_id: str | None
    scope: str | None
    detected_by: str
    created_at: datetime
    updated_at: datetime

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
            "machine_id",
            validate_uuid(
                self.machine_id,
                field_name="machine_id",
            ),
        )

        object.__setattr__(
            self,
            "component_type",
            normalize_choice(
                self.component_type,
                field_name="component_type",
                allowed_values=SUPPORTED_COMPONENT_TYPES,
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
            "normalized_name",
            normalize_optional_text(
                self.normalized_name,
                field_name="normalized_name",
                lowercase=True,
            ),
        )

        object.__setattr__(
            self,
            "version",
            normalize_optional_text(
                self.version,
                field_name="version",
            ),
        )

        object.__setattr__(
            self,
            "vendor",
            normalize_optional_text(
                self.vendor,
                field_name="vendor",
            ),
        )

        object.__setattr__(
            self,
            "normalized_vendor",
            normalize_optional_text(
                self.normalized_vendor,
                field_name="normalized_vendor",
                lowercase=True,
            ),
        )

        object.__setattr__(
            self,
            "ecosystem",
            normalize_optional_text(
                self.ecosystem,
                field_name="ecosystem",
                lowercase=True,
            ),
        )

        object.__setattr__(
            self,
            "external_id",
            normalize_optional_text(
                self.external_id,
                field_name="external_id",
            ),
        )

        object.__setattr__(
            self,
            "scope",
            normalize_optional_text(
                self.scope,
                field_name="scope",
                lowercase=True,
            ),
        )

        object.__setattr__(
            self,
            "detected_by",
            normalize_required_text(
                self.detected_by,
                field_name="detected_by",
                lowercase=True,
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

        object.__setattr__(
            self,
            "updated_at",
            normalize_datetime_utc(
                self.updated_at,
                field_name="updated_at",
            ),
        )

        if (
            self.normalized_vendor is not None
            and self.vendor is None
        ):
            raise ValueError(
                "normalized_vendor requires vendor"
            )

        if self.component_type == "application":
            if self.ecosystem is not None:
                raise ValueError(
                    "application ecosystem must be None"
                )

            if self.scope is not None:
                raise ValueError(
                    "application scope must be None"
                )

            if self.external_id is None:
                raise ValueError(
                    "application external_id is required"
                )

        if self.component_type == "package":
            if self.ecosystem is None:
                raise ValueError(
                    "package ecosystem is required"
                )

            if self.version is None:
                raise ValueError(
                    "package version is required"
                )

            if self.scope is None:
                raise ValueError(
                    "package scope is required"
                )

            if self.external_id is not None:
                raise ValueError(
                    "package external_id must be None"
                )

        if self.updated_at < self.created_at:
            raise ValueError(
                "updated_at must be greater than or equal to created_at"
            )