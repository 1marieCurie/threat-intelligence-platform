from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import (
    datetime,
    timezone,
)
from typing import ClassVar
from uuid import UUID


@dataclass(
    frozen=True,
    slots=True,
)
class WebIndicatorObservation:
    """
    Observation reliant une source normalisée à une URL canonique.

    L'identité logique d'une observation est :

        (source, source_record_key)

    Aucun payload brut ou secret fournisseur n'est conservé.
    """

    source: str
    source_record_key: str
    normalized_record_id: UUID
    observed_at: datetime
    normalizer_version: str

    last_observed_at: datetime | None = None
    source_status: str | None = None
    is_active: bool | None = None

    labels: tuple[
        str,
        ...,
    ] = ()

    MAX_SOURCE_LENGTH: ClassVar[int] = 50
    MAX_RECORD_KEY_LENGTH: ClassVar[int] = 255
    MAX_STATUS_LENGTH: ClassVar[int] = 64
    MAX_LABEL_LENGTH: ClassVar[int] = 64
    MAX_NORMALIZER_VERSION_LENGTH: ClassVar[int] = 30
    MAX_LABELS: ClassVar[int] = 20

    CLASSIFICATION_PATTERN: ClassVar[
        re.Pattern[str]
    ] = re.compile(
        r"^[a-z][a-z0-9_]*$"
    )

    def __post_init__(self) -> None:
        normalized_source = (
            self._normalize_classification(
                self.source,
                field_name="source",
                max_length=(
                    self.MAX_SOURCE_LENGTH
                ),
            )
        )

        normalized_source_record_key = (
            self._normalize_required_text(
                self.source_record_key,
                field_name=(
                    "source_record_key"
                ),
                max_length=(
                    self.MAX_RECORD_KEY_LENGTH
                ),
            )
        )

        normalized_record_id = (
            self._validate_uuid(
                self.normalized_record_id,
                field_name=(
                    "normalized_record_id"
                ),
            )
        )

        normalized_observed_at = (
            self._normalize_datetime(
                self.observed_at,
                field_name="observed_at",
            )
        )

        normalized_last_observed_at = (
            normalized_observed_at
            if self.last_observed_at is None
            else self._normalize_datetime(
                self.last_observed_at,
                field_name=(
                    "last_observed_at"
                ),
            )
        )

        if (
            normalized_last_observed_at
            < normalized_observed_at
        ):
            raise ValueError(
                "last_observed_at must not be "
                "before observed_at"
            )

        normalized_version = (
            self._normalize_required_text(
                self.normalizer_version,
                field_name=(
                    "normalizer_version"
                ),
                max_length=(
                    self
                    .MAX_NORMALIZER_VERSION_LENGTH
                ),
            )
        )

        normalized_source_status = (
            None
            if self.source_status is None
            else self._normalize_classification(
                self.source_status,
                field_name="source_status",
                max_length=(
                    self.MAX_STATUS_LENGTH
                ),
            )
        )

        normalized_is_active = (
            self._normalize_optional_boolean(
                self.is_active
            )
        )

        normalized_labels = (
            self._normalize_labels(
                self.labels
            )
        )

        object.__setattr__(
            self,
            "source",
            normalized_source,
        )

        object.__setattr__(
            self,
            "source_record_key",
            normalized_source_record_key,
        )

        object.__setattr__(
            self,
            "normalized_record_id",
            normalized_record_id,
        )

        object.__setattr__(
            self,
            "observed_at",
            normalized_observed_at,
        )

        object.__setattr__(
            self,
            "last_observed_at",
            normalized_last_observed_at,
        )

        object.__setattr__(
            self,
            "normalizer_version",
            normalized_version,
        )

        object.__setattr__(
            self,
            "source_status",
            normalized_source_status,
        )

        object.__setattr__(
            self,
            "is_active",
            normalized_is_active,
        )

        object.__setattr__(
            self,
            "labels",
            normalized_labels,
        )

    @property
    def key(
        self,
    ) -> tuple[str, str]:
        return (
            self.source,
            self.source_record_key,
        )

    @classmethod
    def _normalize_labels(
        cls,
        values: Iterable[str],
    ) -> tuple[str, ...]:
        if isinstance(
            values,
            (str, bytes),
        ):
            raise TypeError(
                "labels must be an iterable "
                "of strings"
            )

        try:
            bounded_values = tuple(
                values
            )

        except TypeError as error:
            raise TypeError(
                "labels must be an iterable "
                "of strings"
            ) from error

        if (
            len(bounded_values)
            > cls.MAX_LABELS
        ):
            raise ValueError(
                "labels must not contain more than "
                f"{cls.MAX_LABELS} values"
            )

        normalized_labels: list[str] = []
        seen: set[str] = set()

        for value in bounded_values:
            normalized_value = (
                cls._normalize_classification(
                    value,
                    field_name="label",
                    max_length=(
                        cls.MAX_LABEL_LENGTH
                    ),
                )
            )

            if normalized_value in seen:
                continue

            seen.add(
                normalized_value
            )

            normalized_labels.append(
                normalized_value
            )

        return tuple(
            normalized_labels
        )

    @classmethod
    def _normalize_classification(
        cls,
        value: str,
        *,
        field_name: str,
        max_length: int,
    ) -> str:
        normalized_value = (
            cls._normalize_required_text(
                value,
                field_name=field_name,
                max_length=max_length,
            )
            .lower()
        )

        if (
            cls.CLASSIFICATION_PATTERN
            .fullmatch(
                normalized_value
            )
            is None
        ):
            raise ValueError(
                f"{field_name} must use "
                "lowercase snake_case"
            )

        return normalized_value

    @staticmethod
    def _normalize_required_text(
        value: str,
        *,
        field_name: str,
        max_length: int,
    ) -> str:
        if not isinstance(value, str):
            raise TypeError(
                f"{field_name} must be a string"
            )

        normalized_value = value.strip()

        if not normalized_value:
            raise ValueError(
                f"{field_name} must not be empty"
            )

        if (
            len(normalized_value)
            > max_length
        ):
            raise ValueError(
                f"{field_name} must not exceed "
                f"{max_length} characters"
            )

        if any(
            ord(character) < 32
            or ord(character) == 127
            for character in normalized_value
        ):
            raise ValueError(
                f"{field_name} must not contain "
                "control characters"
            )

        return normalized_value

    @staticmethod
    def _validate_uuid(
        value: UUID,
        *,
        field_name: str,
    ) -> UUID:
        if not isinstance(value, UUID):
            raise TypeError(
                f"{field_name} must be a UUID"
            )

        if value.int == 0:
            raise ValueError(
                f"{field_name} must not be "
                "the nil UUID"
            )

        return value

    @staticmethod
    def _normalize_datetime(
        value: datetime,
        *,
        field_name: str,
    ) -> datetime:
        if not isinstance(value, datetime):
            raise TypeError(
                f"{field_name} must be a datetime"
            )

        if (
            value.tzinfo is None
            or value.utcoffset() is None
        ):
            raise ValueError(
                f"{field_name} must be "
                "timezone-aware"
            )

        return value.astimezone(
            timezone.utc
        )

    @staticmethod
    def _normalize_optional_boolean(
        value: bool | None,
    ) -> bool | None:
        if value is None:
            return None

        if not isinstance(value, bool):
            raise TypeError(
                "is_active must be "
                "a boolean or None"
            )

        return value