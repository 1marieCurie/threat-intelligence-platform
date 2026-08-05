from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import (
    datetime,
    timezone,
)
from hashlib import sha256
from typing import ClassVar
from uuid import UUID

from domain.web_indicator_observation import (
    WebIndicatorObservation,
)


@dataclass(
    frozen=True,
    slots=True,
)
class CanonicalWebIndicator:
    """
    Identité canonique d'une URL observée comme dangereuse.

    L'agrégat est source-neutral. Il ne contient ni payload brut,
    ni appel réseau, ni résultat de modèle IA.
    """

    id: UUID
    canonical_value: str
    value_hash: str
    hostname: str

    observations: tuple[
        WebIndicatorObservation,
        ...,
    ]

    created_at: datetime
    updated_at: datetime

    indicator_type: str = "url"
    canonicalization_version: int = 1

    MAX_URL_LENGTH: ClassVar[int] = 4_096
    MAX_HOSTNAME_LENGTH: ClassVar[int] = 253

    SHA256_PATTERN: ClassVar[
        re.Pattern[str]
    ] = re.compile(
        r"^[a-f0-9]{64}$"
    )

    def __post_init__(self) -> None:
        normalized_id = self._validate_uuid(
            self.id
        )

        normalized_value = (
            self._normalize_canonical_value(
                self.canonical_value
            )
        )

        normalized_hash = (
            self._normalize_value_hash(
                value=self.value_hash,
                canonical_value=(
                    normalized_value
                ),
            )
        )

        normalized_hostname = (
            self._normalize_hostname(
                self.hostname
            )
        )

        normalized_observations = (
            self._normalize_observations(
                self.observations
            )
        )

        normalized_created_at = (
            self._normalize_datetime(
                self.created_at,
                field_name="created_at",
            )
        )

        normalized_updated_at = (
            self._normalize_datetime(
                self.updated_at,
                field_name="updated_at",
            )
        )

        if (
            normalized_updated_at
            < normalized_created_at
        ):
            raise ValueError(
                "updated_at must not be "
                "before created_at"
            )

        normalized_indicator_type = (
            self._normalize_indicator_type(
                self.indicator_type
            )
        )

        normalized_version = (
            self._normalize_version(
                self.canonicalization_version
            )
        )

        object.__setattr__(
            self,
            "id",
            normalized_id,
        )

        object.__setattr__(
            self,
            "canonical_value",
            normalized_value,
        )

        object.__setattr__(
            self,
            "value_hash",
            normalized_hash,
        )

        object.__setattr__(
            self,
            "hostname",
            normalized_hostname,
        )

        object.__setattr__(
            self,
            "observations",
            normalized_observations,
        )

        object.__setattr__(
            self,
            "created_at",
            normalized_created_at,
        )

        object.__setattr__(
            self,
            "updated_at",
            normalized_updated_at,
        )

        object.__setattr__(
            self,
            "indicator_type",
            normalized_indicator_type,
        )

        object.__setattr__(
            self,
            "canonicalization_version",
            normalized_version,
        )

    @property
    def first_seen_at(
        self,
    ) -> datetime:
        return min(
            observation.observed_at
            for observation
            in self.observations
        )

    @property
    def last_seen_at(
        self,
    ) -> datetime:
        return max(
            (
                observation.last_observed_at
                or observation.observed_at
            )
            for observation
            in self.observations
        )

    @property
    def sources(
        self,
    ) -> tuple[str, ...]:
        return tuple(
            dict.fromkeys(
                observation.source
                for observation
                in self.observations
            )
        )

    @property
    def labels(
        self,
    ) -> tuple[str, ...]:
        return tuple(
            dict.fromkeys(
                label
                for observation
                in self.observations
                for label
                in observation.labels
            )
        )

    @staticmethod
    def _validate_uuid(
        value: UUID,
    ) -> UUID:
        if not isinstance(value, UUID):
            raise TypeError(
                "id must be a UUID"
            )

        if value.int == 0:
            raise ValueError(
                "id must not be the nil UUID"
            )

        return value

    @classmethod
    def _normalize_canonical_value(
        cls,
        value: str,
    ) -> str:
        if not isinstance(value, str):
            raise TypeError(
                "canonical_value must be a string"
            )

        normalized_value = value.strip()

        if not normalized_value:
            raise ValueError(
                "canonical_value must not be empty"
            )

        if (
            len(normalized_value)
            > cls.MAX_URL_LENGTH
        ):
            raise ValueError(
                "canonical_value must not exceed "
                f"{cls.MAX_URL_LENGTH} characters"
            )

        if any(
            character.isspace()
            or ord(character) < 32
            or ord(character) == 127
            for character in normalized_value
        ):
            raise ValueError(
                "canonical_value contains "
                "invalid characters"
            )

        return normalized_value

    @classmethod
    def _normalize_value_hash(
        cls,
        *,
        value: str,
        canonical_value: str,
    ) -> str:
        if not isinstance(value, str):
            raise TypeError(
                "value_hash must be a string"
            )

        normalized_value = (
            value
            .strip()
            .lower()
        )

        if (
            cls.SHA256_PATTERN.fullmatch(
                normalized_value
            )
            is None
        ):
            raise ValueError(
                "value_hash must be a "
                "SHA-256 hexadecimal value"
            )

        expected_hash = sha256(
            canonical_value.encode(
                "utf-8"
            )
        ).hexdigest()

        if normalized_value != expected_hash:
            raise ValueError(
                "value_hash does not match "
                "canonical_value"
            )

        return normalized_value

    @classmethod
    def _normalize_hostname(
        cls,
        value: str,
    ) -> str:
        if not isinstance(value, str):
            raise TypeError(
                "hostname must be a string"
            )

        normalized_value = (
            value
            .strip()
            .lower()
            .rstrip(".")
        )

        if not normalized_value:
            raise ValueError(
                "hostname must not be empty"
            )

        if (
            len(normalized_value)
            > cls.MAX_HOSTNAME_LENGTH
        ):
            raise ValueError(
                "hostname must not exceed "
                f"{cls.MAX_HOSTNAME_LENGTH} characters"
            )

        if any(
            character.isspace()
            or ord(character) < 32
            or ord(character) == 127
            for character in normalized_value
        ):
            raise ValueError(
                "hostname contains invalid characters"
            )

        return normalized_value

    @staticmethod
    def _normalize_observations(
        values: Iterable[
            WebIndicatorObservation
        ],
    ) -> tuple[
        WebIndicatorObservation,
        ...,
    ]:
        if isinstance(
            values,
            (str, bytes),
        ):
            raise TypeError(
                "observations must be an iterable "
                "of WebIndicatorObservation objects"
            )

        try:
            normalized_values = tuple(
                values
            )

        except TypeError as error:
            raise TypeError(
                "observations must be an iterable "
                "of WebIndicatorObservation objects"
            ) from error

        if not normalized_values:
            raise ValueError(
                "A canonical web indicator must "
                "contain at least one observation"
            )

        for observation in normalized_values:
            if not isinstance(
                observation,
                WebIndicatorObservation,
            ):
                raise TypeError(
                    "Every observation must be a "
                    "WebIndicatorObservation"
                )

        keys = [
            observation.key
            for observation
            in normalized_values
        ]

        if len(keys) != len(set(keys)):
            raise ValueError(
                "Web indicator observations must "
                "be unique by source record"
            )

        return normalized_values

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
    def _normalize_indicator_type(
        value: str,
    ) -> str:
        if not isinstance(value, str):
            raise TypeError(
                "indicator_type must be a string"
            )

        normalized_value = (
            value
            .strip()
            .lower()
        )

        if normalized_value != "url":
            raise ValueError(
                "indicator_type must be url"
            )

        return normalized_value

    @staticmethod
    def _normalize_version(
        value: int,
    ) -> int:
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
        ):
            raise TypeError(
                "canonicalization_version "
                "must be an integer"
            )

        if value < 1:
            raise ValueError(
                "canonicalization_version must "
                "be greater than zero"
            )

        return value