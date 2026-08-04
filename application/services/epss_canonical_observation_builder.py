from __future__ import annotations

from datetime import (
    UTC,
    datetime,
)

from application.models.canonical_vulnerability_observation import (
    CanonicalVulnerabilityObservation,
)
from application.models.epss_snapshot import (
    EPSSSnapshot,
)
from domain.vulnerability_evidence import (
    VulnerabilityEvidence,
)
from domain.vulnerability_identifier import (
    VulnerabilityIdentifier,
)


class EPSSCanonicalObservationBuilder:
    """
    Construit une observation canonique à partir
    d'un score EPSS normalisé.

    Le builder :

    - ne réalise aucun appel réseau ;
    - ne lit aucun payload brut ;
    - ne persiste aucune donnée ;
    - ne copie pas le score EPSS dans la couche canonique ;
    - produit uniquement une corrélation exacte par CVE.
    """

    SOURCE = "epss"
    EVIDENCE_TYPE = "epss_snapshot"
    CORRELATION_RULE = "exact_cve"

    def build(
        self,
        *,
        cve_id: str,
        snapshot: EPSSSnapshot,
        synchronized_at: datetime,
    ) -> CanonicalVulnerabilityObservation:
        if not isinstance(
            snapshot,
            EPSSSnapshot,
        ):
            raise TypeError(
                "snapshot must be an EPSSSnapshot"
            )

        observed_at = (
            self._normalize_synchronized_at(
                synchronized_at
            )
        )

        identifier = VulnerabilityIdentifier(
            namespace="CVE",
            value=cve_id,
            is_primary=True,
        )

        score_published_at = datetime(
            snapshot.score_date.year,
            snapshot.score_date.month,
            snapshot.score_date.day,
            tzinfo=UTC,
        )

        evidence = VulnerabilityEvidence(
            source=self.SOURCE,
            source_record_key=(
                identifier.value
            ),
            normalized_record_id=(
                identifier.value
            ),
            evidence_type=(
                self.EVIDENCE_TYPE
            ),
            correlation_rule=(
                self.CORRELATION_RULE
            ),
            observed_at=observed_at,
            last_observed_at=observed_at,
            source_published_at=(
                score_published_at
            ),
            correlation_confidence=1.0,
        )

        return CanonicalVulnerabilityObservation(
            identifiers=(
                identifier,
            ),
            evidence=evidence,
            suggested_status="provisional",
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