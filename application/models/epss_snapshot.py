from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime
from math import isfinite


@dataclass(
    frozen=True,
    slots=True,
)
class EPSSSnapshot:
    """
    Valeur d'enrichissement EPSS associée à un CVE.

    Ce modèle ne possède pas d'identité propre :
    l'association avec le CVE est gérée par le repository.
    """

    score: float
    percentile: float
    score_date: date
    api_version: str | None = None

    def __post_init__(self) -> None:
        normalized_score = self._validate_probability(
            self.score,
            field_name="score",
        )
        normalized_percentile = self._validate_probability(
            self.percentile,
            field_name="percentile",
        )

        if (
            not isinstance(self.score_date, date)
            or isinstance(self.score_date, datetime)
        ):
            raise TypeError(
                "score_date must be a date"
            )

        normalized_api_version = self._validate_api_version(
            self.api_version
        )

        object.__setattr__(
            self,
            "score",
            normalized_score,
        )
        object.__setattr__(
            self,
            "percentile",
            normalized_percentile,
        )
        object.__setattr__(
            self,
            "api_version",
            normalized_api_version,
        )

    @staticmethod
    def _validate_probability(
        value: float,
        *,
        field_name: str,
    ) -> float:
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
        ):
            raise TypeError(
                f"{field_name} must be a number"
            )

        normalized_value = float(value)

        if not isfinite(normalized_value):
            raise ValueError(
                f"{field_name} must be finite"
            )

        if not 0.0 <= normalized_value <= 1.0:
            raise ValueError(
                f"{field_name} must be between 0 and 1"
            )

        return normalized_value

    @staticmethod
    def _validate_api_version(
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        if not isinstance(value, str):
            raise TypeError(
                "api_version must be a string or None"
            )

        normalized_value = value.strip()

        if not normalized_value:
            raise ValueError(
                "api_version must not be empty"
            )

        if len(normalized_value) > 20:
            raise ValueError(
                "api_version must not exceed 20 characters"
            )

        return normalized_value