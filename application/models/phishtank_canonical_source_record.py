from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from application.models._canonical_web_source_validation import (
    normalize_datetime,
    normalize_optional_boolean,
    normalize_optional_datetime,
    normalize_positive_integer,
    normalize_required_text,
    normalize_uuid,
)


@dataclass(
    frozen=True,
    slots=True,
)
class PhishTankCanonicalCursor:
    phish_id: int
    normalized_record_id: UUID

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "phish_id",
            normalize_positive_integer(
                self.phish_id,
                field_name="phish_id",
            ),
        )

        object.__setattr__(
            self,
            "normalized_record_id",
            normalize_uuid(
                self.normalized_record_id,
                field_name=(
                    "normalized_record_id"
                ),
            ),
        )


@dataclass(
    frozen=True,
    slots=True,
)
class PhishTankCanonicalSourceRecord:
    normalized_record_id: UUID
    phish_id: int
    phishing_url: str
    normalized_at: datetime
    normalizer_version: str

    submission_time: datetime | None = None
    verification_time: datetime | None = None

    verified: bool | None = None
    online: bool | None = None

    MAX_URL_LENGTH = 4_096
    MAX_VERSION_LENGTH = 30

    def __post_init__(self) -> None:
        normalized_record_id = normalize_uuid(
            self.normalized_record_id,
            field_name="normalized_record_id",
        )

        phish_id = normalize_positive_integer(
            self.phish_id,
            field_name="phish_id",
        )

        phishing_url = normalize_required_text(
            self.phishing_url,
            field_name="phishing_url",
            max_length=self.MAX_URL_LENGTH,
        )

        normalized_at = normalize_datetime(
            self.normalized_at,
            field_name="normalized_at",
        )

        normalizer_version = (
            normalize_required_text(
                self.normalizer_version,
                field_name="normalizer_version",
                max_length=(
                    self.MAX_VERSION_LENGTH
                ),
            )
        )

        submission_time = (
            normalize_optional_datetime(
                self.submission_time,
                field_name="submission_time",
            )
        )

        verification_time = (
            normalize_optional_datetime(
                self.verification_time,
                field_name="verification_time",
            )
        )

        if (
            submission_time is not None
            and verification_time is not None
            and verification_time
            < submission_time
        ):
            raise ValueError(
                "verification_time must not be "
                "before submission_time"
            )

        verified = normalize_optional_boolean(
            self.verified,
            field_name="verified",
        )

        online = normalize_optional_boolean(
            self.online,
            field_name="online",
        )

        object.__setattr__(
            self,
            "normalized_record_id",
            normalized_record_id,
        )

        object.__setattr__(
            self,
            "phish_id",
            phish_id,
        )

        object.__setattr__(
            self,
            "phishing_url",
            phishing_url,
        )

        object.__setattr__(
            self,
            "normalized_at",
            normalized_at,
        )

        object.__setattr__(
            self,
            "normalizer_version",
            normalizer_version,
        )

        object.__setattr__(
            self,
            "submission_time",
            submission_time,
        )

        object.__setattr__(
            self,
            "verification_time",
            verification_time,
        )

        object.__setattr__(
            self,
            "verified",
            verified,
        )

        object.__setattr__(
            self,
            "online",
            online,
        )

    @property
    def cursor(
        self,
    ) -> PhishTankCanonicalCursor:
        return PhishTankCanonicalCursor(
            phish_id=self.phish_id,
            normalized_record_id=(
                self.normalized_record_id
            ),
        )