from __future__ import annotations

from dataclasses import dataclass
from datetime import (
    UTC,
    date,
    datetime,
)
from uuid import UUID

from domain.vulnerability_identifier import (
    VulnerabilityIdentifier,
)


@dataclass(
    frozen=True,
    slots=True,
)
class CisaKevCanonicalCursor:
    """
    Curseur stable de pagination CISA KEV.

    Le CVE seul n'est pas suffisant, car plusieurs lignes
    normalisées peuvent représenter le même CVE.
    """

    cve_id: str
    normalized_record_id: UUID

    def __post_init__(self) -> None:
        if not isinstance(
            self.normalized_record_id,
            UUID,
        ):
            raise TypeError(
                "normalized_record_id must be a UUID"
            )

        normalized_cve_id = (
            VulnerabilityIdentifier(
                namespace="CVE",
                value=self.cve_id,
                is_primary=True,
            ).value
        )

        object.__setattr__(
            self,
            "cve_id",
            normalized_cve_id,
        )


@dataclass(
    frozen=True,
    slots=True,
)
class CisaKevCanonicalSourceRecord:
    """
    Projection minimale d'une vulnérabilité CISA KEV
    normalisée destinée à la corrélation canonique.

    Aucun payload brut, texte descriptif ou détail
    opérationnel n'est exposé.
    """

    normalized_record_id: UUID
    cve_id: str
    date_added: date
    normalized_at: datetime

    def __post_init__(self) -> None:
        cursor = CisaKevCanonicalCursor(
            cve_id=self.cve_id,
            normalized_record_id=(
                self.normalized_record_id
            ),
        )

        if (
            not isinstance(
                self.date_added,
                date,
            )
            or isinstance(
                self.date_added,
                datetime,
            )
        ):
            raise TypeError(
                "date_added must be a date"
            )

        normalized_at = (
            self._normalize_datetime(
                self.normalized_at,
                field_name="normalized_at",
            )
        )

        object.__setattr__(
            self,
            "cve_id",
            cursor.cve_id,
        )

        object.__setattr__(
            self,
            "normalized_at",
            normalized_at,
        )

    @property
    def cursor(
        self,
    ) -> CisaKevCanonicalCursor:
        return CisaKevCanonicalCursor(
            cve_id=self.cve_id,
            normalized_record_id=(
                self.normalized_record_id
            ),
        )

    @staticmethod
    def _normalize_datetime(
        value: datetime,
        *,
        field_name: str,
    ) -> datetime:
        if not isinstance(
            value,
            datetime,
        ):
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
            UTC
        )