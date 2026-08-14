from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar
from uuid import UUID

from domain._asset_validation import (
    normalize_choice,
    normalize_datetime_utc,
    normalize_required_text,
    validate_bool,
    validate_uuid,
)


@dataclass(
    frozen=True,
    slots=True,
)
class UserAccount:
    id: UUID
    organization_id: UUID
    email: str
    display_name: str
    role: str
    is_active: bool
    created_at: datetime

    SUPPORTED_ROLES: ClassVar[
        frozenset[str]
    ] = frozenset(
        {
            "security_responsible",
            "staff",
        }
    )

    def __post_init__(self) -> None:
        normalized_email = (
            normalize_required_text(
                self.email,
                field_name="email",
                lowercase=True,
            )
        )

        if (
            "@" not in normalized_email
            or normalized_email.startswith("@")
            or normalized_email.endswith("@")
            or any(
                character.isspace()
                for character in normalized_email
            )
        ):
            raise ValueError(
                "email must be a valid non-empty email address"
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
            "email",
            normalized_email,
        )
        object.__setattr__(
            self,
            "display_name",
            normalize_required_text(
                self.display_name,
                field_name="display_name",
            ),
        )
        object.__setattr__(
            self,
            "role",
            normalize_choice(
                self.role,
                field_name="role",
                allowed_values=self.SUPPORTED_ROLES,
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