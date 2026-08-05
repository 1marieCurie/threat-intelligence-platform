from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from application.models._canonical_web_source_validation import (
    normalize_datetime,
    normalize_optional_datetime,
    normalize_optional_text,
    normalize_positive_integer,
    normalize_required_text,
    normalize_uuid,
)


@dataclass(
    frozen=True,
    slots=True,
)
class URLhausCanonicalCursor:
    urlhaus_id: int
    normalized_record_id: UUID

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "urlhaus_id",
            normalize_positive_integer(
                self.urlhaus_id,
                field_name="urlhaus_id",
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
class URLhausCanonicalSourceRecord:
    normalized_record_id: UUID
    urlhaus_id: int
    malicious_url: str
    normalized_at: datetime
    normalizer_version: str

    date_added: datetime | None = None
    url_status: str | None = None

    MAX_URL_LENGTH = 4_096
    MAX_STATUS_LENGTH = 32
    MAX_VERSION_LENGTH = 30

    def __post_init__(self) -> None:
        normalized_record_id = normalize_uuid(
            self.normalized_record_id,
            field_name="normalized_record_id",
        )

        urlhaus_id = normalize_positive_integer(
            self.urlhaus_id,
            field_name="urlhaus_id",
        )

        malicious_url = normalize_required_text(
            self.malicious_url,
            field_name="malicious_url",
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

        date_added = normalize_optional_datetime(
            self.date_added,
            field_name="date_added",
        )

        url_status = normalize_optional_text(
            self.url_status,
            field_name="url_status",
            max_length=self.MAX_STATUS_LENGTH,
            lowercase=True,
        )

        object.__setattr__(
            self,
            "normalized_record_id",
            normalized_record_id,
        )

        object.__setattr__(
            self,
            "urlhaus_id",
            urlhaus_id,
        )

        object.__setattr__(
            self,
            "malicious_url",
            malicious_url,
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
            "date_added",
            date_added,
        )

        object.__setattr__(
            self,
            "url_status",
            url_status,
        )

    @property
    def cursor(
        self,
    ) -> URLhausCanonicalCursor:
        return URLhausCanonicalCursor(
            urlhaus_id=self.urlhaus_id,
            normalized_record_id=(
                self.normalized_record_id
            ),
        )