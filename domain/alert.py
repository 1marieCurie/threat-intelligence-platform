from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar
from uuid import UUID

from domain._asset_validation import (
    normalize_choice,
    normalize_datetime_utc,
    normalize_required_text,
    validate_uuid,
)


@dataclass(
    frozen=True,
    slots=True,
)
class Alert:
    id: UUID
    organization_id: UUID
    machine_id: UUID
    vulnerability_exposure_id: UUID | None
    canonical_vulnerability_id: UUID
    alert_type: str
    recipient_user_id: UUID
    status: str
    deduplication_key: str
    created_at: datetime
    sent_at: datetime | None

    SUPPORTED_ALERT_TYPES: ClassVar[
        frozenset[str]
    ] = frozenset(
        {
            "new_confirmed_critical_exposure",
            "confirmed_exposure_entered_kev",
            "priority_transition_to_critical",
        }
    )

    SUPPORTED_STATUSES: ClassVar[
        frozenset[str]
    ] = frozenset(
        {
            "pending",
            "sent",
            "failed",
        }
    )

    def __post_init__(self) -> None:
        status = normalize_choice(
            self.status,
            field_name="status",
            allowed_values=self.SUPPORTED_STATUSES,
        )
        created_at = normalize_datetime_utc(
            self.created_at,
            field_name="created_at",
        )

        sent_at = (
            None
            if self.sent_at is None
            else normalize_datetime_utc(
                self.sent_at,
                field_name="sent_at",
            )
        )

        if status == "sent" and sent_at is None:
            raise ValueError(
                "sent_at is required when status is sent"
            )

        if status != "sent" and sent_at is not None:
            raise ValueError(
                "sent_at is only allowed when status is sent"
            )

        if sent_at is not None and sent_at < created_at:
            raise ValueError(
                "sent_at must not be before created_at"
            )

        exposure_id = (
            None
            if self.vulnerability_exposure_id is None
            else validate_uuid(
                self.vulnerability_exposure_id,
                field_name="vulnerability_exposure_id",
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
            "machine_id",
            validate_uuid(
                self.machine_id,
                field_name="machine_id",
            ),
        )
        object.__setattr__(
            self,
            "vulnerability_exposure_id",
            exposure_id,
        )
        object.__setattr__(
            self,
            "canonical_vulnerability_id",
            validate_uuid(
                self.canonical_vulnerability_id,
                field_name="canonical_vulnerability_id",
            ),
        )
        object.__setattr__(
            self,
            "alert_type",
            normalize_choice(
                self.alert_type,
                field_name="alert_type",
                allowed_values=self.SUPPORTED_ALERT_TYPES,
            ),
        )
        object.__setattr__(
            self,
            "recipient_user_id",
            validate_uuid(
                self.recipient_user_id,
                field_name="recipient_user_id",
            ),
        )
        object.__setattr__(
            self,
            "status",
            status,
        )
        object.__setattr__(
            self,
            "deduplication_key",
            normalize_required_text(
                self.deduplication_key,
                field_name="deduplication_key",
            ),
        )
        object.__setattr__(
            self,
            "created_at",
            created_at,
        )
        object.__setattr__(
            self,
            "sent_at",
            sent_at,
        )