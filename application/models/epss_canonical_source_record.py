from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from application.models.epss_snapshot import (
    EPSSSnapshot,
)
from domain.vulnerability_identifier import (
    VulnerabilityIdentifier,
)


@dataclass(
    frozen=True,
    slots=True,
)
class EPSSCanonicalSourceRecord:
    """
    Projection minimale d'une ligne EPSS normalisée.

    Aucun payload brut ni champ fournisseur supplémentaire
    n'est exposé à la couche canonique.
    """

    cve_id: str
    snapshot: EPSSSnapshot
    synchronized_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(
            self.snapshot,
            EPSSSnapshot,
        ):
            raise TypeError(
                "snapshot must be an EPSSSnapshot"
            )

        normalized_cve_id = (
            VulnerabilityIdentifier(
                namespace="CVE",
                value=self.cve_id,
                is_primary=True,
            ).value
        )

        normalized_synchronized_at = (
            self._normalize_synchronized_at(
                self.synchronized_at
            )
        )

        object.__setattr__(
            self,
            "cve_id",
            normalized_cve_id,
        )

        object.__setattr__(
            self,
            "synchronized_at",
            normalized_synchronized_at,
        )

    @staticmethod
    def _normalize_synchronized_at(
        value: datetime,
    ) -> datetime:
        if not isinstance(
            value,
            datetime,
        ):
            raise TypeError(
                "synchronized_at must be "
                "a datetime"
            )

        if (
            value.tzinfo is None
            or value.utcoffset() is None
        ):
            raise ValueError(
                "synchronized_at must be "
                "timezone-aware"
            )

        return value.astimezone(
            UTC
        )