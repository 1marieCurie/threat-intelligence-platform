from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import (
    datetime,
    timezone,
)
from math import isfinite


SUPPORTED_SOURCE_ROLES = frozenset(
    {
        "VENDOR",
        "CNA",
        "NVD",
        "ADP",
        "THIRD_PARTY",
    }
)


@dataclass(
    frozen=True,
    slots=True,
)
class CvssObservation:
    source_name: str
    version: str
    base_score: float

    vector: str | None = None
    source_role: str | None = None

    published_at: datetime | None = None
    modified_at: datetime | None = None

    def __post_init__(self) -> None:
        source_name = (
            self.source_name
            .strip()
            .lower()
        )

        if not source_name:
            raise ValueError(
                "source_name must not be empty"
            )

        version = (
            CvssSelectionPolicyV1
            .normalize_version(
                self.version
            )
        )

        if version is None:
            raise ValueError(
                "Unsupported CVSS version"
            )

        if (
            isinstance(
                self.base_score,
                bool,
            )
            or not isinstance(
                self.base_score,
                (int, float),
            )
        ):
            raise TypeError(
                "base_score must be a number"
            )

        base_score = float(
            self.base_score
        )

        if (
            not isfinite(base_score)
            or not 0.0
            <= base_score
            <= 10.0
        ):
            raise ValueError(
                "base_score must be "
                "between 0 and 10"
            )

        vector = (
            None
            if self.vector is None
            else self.vector.strip() or None
        )

        source_role = (
            None
            if self.source_role is None
            else (
                self.source_role
                .strip()
                .upper()
            )
        )

        if (
            source_role is not None
            and source_role
            not in SUPPORTED_SOURCE_ROLES
        ):
            raise ValueError(
                "Unsupported CVSS source_role"
            )

        published_at = (
            self._normalize_datetime(
                self.published_at,
                field_name="published_at",
            )
        )

        modified_at = (
            self._normalize_datetime(
                self.modified_at,
                field_name="modified_at",
            )
        )

        object.__setattr__(
            self,
            "source_name",
            source_name,
        )

        object.__setattr__(
            self,
            "version",
            version,
        )

        object.__setattr__(
            self,
            "base_score",
            base_score,
        )

        object.__setattr__(
            self,
            "vector",
            vector,
        )

        object.__setattr__(
            self,
            "source_role",
            source_role,
        )

        object.__setattr__(
            self,
            "published_at",
            published_at,
        )

        object.__setattr__(
            self,
            "modified_at",
            modified_at,
        )

    @staticmethod
    def _normalize_datetime(
        value: datetime | None,
        *,
        field_name: str,
    ) -> datetime | None:
        if value is None:
            return None

        if not isinstance(
            value,
            datetime,
        ):
            raise TypeError(
                f"{field_name} must be "
                "a datetime or None"
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


@dataclass(
    frozen=True,
    slots=True,
)
class SelectedCvss:
    version: str
    base_score: float

    source_name: str
    source_role: str | None

    vector: str | None

    published_at: datetime | None
    modified_at: datetime | None

    selection_policy_version: str


class CvssSelectionPolicyV1:
    """
    Sélection déterministe du CVSS Base utilisé
    par la plateforme.

    Ordre métier :

        version CVSS
        > autorité de source
        > fraîcheur
        > tie-break déterministe

    La valeur du score elle-même ne sert jamais
    à préférer une observation à une autre.
    """

    POLICY_VERSION = "1.0.0"

    _VERSION_PRIORITY = {
        "4.0": 0,
        "3.1": 1,
        "3.0": 2,

        # Compatibilité avec les données qui
        # indiquent seulement "CVSS v3".
        #
        # On ne prétend pas qu'il s'agit de 3.1.
        "3.x": 3,

        "2.0": 4,
    }

    _SOURCE_TIER = {
        "VENDOR": 0,
        "CNA": 0,

        "NVD": 1,
        "ADP": 1,

        "THIRD_PARTY": 2,

        None: 3,
    }

    _SOURCE_PREFERENCE = {
        # Même tier VENDOR/CNA,
        # mais légère préférence au vendor.
        "VENDOR": 0,
        "CNA": 1,

        # NVD/ADP restent au même niveau.
        "NVD": 0,
        "ADP": 0,

        "THIRD_PARTY": 0,
        None: 0,
    }

    def select(
        self,
        observations: Iterable[
            CvssObservation
        ],
    ) -> SelectedCvss | None:
        if isinstance(
            observations,
            (str, bytes),
        ):
            raise TypeError(
                "observations must be an "
                "iterable of CvssObservation"
            )

        values = tuple(
            observations
        )

        if not values:
            return None

        for observation in values:
            if not isinstance(
                observation,
                CvssObservation,
            ):
                raise TypeError(
                    "Every observation must "
                    "be a CvssObservation"
                )

        selected = min(
            values,
            key=self._selection_key,
        )

        return SelectedCvss(
            version=selected.version,
            base_score=(
                selected.base_score
            ),
            source_name=(
                selected.source_name
            ),
            source_role=(
                selected.source_role
            ),
            vector=selected.vector,
            published_at=(
                selected.published_at
            ),
            modified_at=(
                selected.modified_at
            ),
            selection_policy_version=(
                self.POLICY_VERSION
            ),
        )

    @classmethod
    def _selection_key(
        cls,
        observation: CvssObservation,
    ) -> tuple[
        int,
        int,
        int,
        int,
        float,
        str,
        str,
    ]:
        freshness = (
            observation.modified_at
            or observation.published_at
        )

        if freshness is None:
            freshness_missing = 1
            freshness_value = 0.0
        else:
            freshness_missing = 0

            # Le plus récent doit être sélectionné,
            # donc timestamp négatif avec min().
            freshness_value = (
                -freshness.timestamp()
            )

        return (
            cls._VERSION_PRIORITY[
                observation.version
            ],
            cls._SOURCE_TIER[
                observation.source_role
            ],
            cls._SOURCE_PREFERENCE[
                observation.source_role
            ],
            freshness_missing,
            freshness_value,
            observation.source_name,
            observation.vector or "",
        )

    @staticmethod
    def normalize_version(
        value: str,
    ) -> str | None:
        if not isinstance(
            value,
            str,
        ):
            raise TypeError(
                "CVSS version must be a string"
            )

        normalized = (
            value.strip().upper()
        )

        if normalized.startswith(
            "CVSS:"
        ):
            normalized = (
                normalized
                .split(
                    "/",
                    1,
                )[0]
                .partition(":")[2]
            )

        aliases = {
            "4": "4.0",
            "4.0": "4.0",

            "3.1": "3.1",
            "3.0": "3.0",

            # GitHub peut conserver uniquement
            # la famille v3 lorsque le vector
            # ne fournit pas la version exacte.
            "3": "3.x",
            "3.X": "3.x",

            "2": "2.0",
            "2.0": "2.0",
        }

        return aliases.get(
            normalized
        )