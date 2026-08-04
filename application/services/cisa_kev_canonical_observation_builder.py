from __future__ import annotations

from datetime import (
    UTC,
    datetime,
)

from application.models.canonical_vulnerability_observation import (
    CanonicalVulnerabilityObservation,
)
from application.models.cisa_kev_canonical_source_record import (
    CisaKevCanonicalSourceRecord,
)
from domain.vulnerability_evidence import (
    VulnerabilityEvidence,
)
from domain.vulnerability_identifier import (
    VulnerabilityIdentifier,
)


class CisaKevCanonicalObservationBuilder:
    """
    Construit une observation canonique depuis une ligne
    normalisée du catalogue CISA KEV.

    Une entrée KEV constitue une preuve fiable que la
    vulnérabilité est activement exploitée. Elle propose
    donc le statut canonique active.
    """

    SOURCE = "cisa_kev"
    EVIDENCE_TYPE = (
        "known_exploited_vulnerability"
    )
    CORRELATION_RULE = "exact_cve"

    def build(
        self,
        *,
        record: CisaKevCanonicalSourceRecord,
    ) -> CanonicalVulnerabilityObservation:
        if not isinstance(
            record,
            CisaKevCanonicalSourceRecord,
        ):
            raise TypeError(
                "record must be a "
                "CisaKevCanonicalSourceRecord"
            )

        identifier = VulnerabilityIdentifier(
            namespace="CVE",
            value=record.cve_id,
            is_primary=True,
        )

        source_published_at = datetime(
            record.date_added.year,
            record.date_added.month,
            record.date_added.day,
            tzinfo=UTC,
        )

        evidence = VulnerabilityEvidence(
            source=self.SOURCE,
            source_record_key=(
                identifier.value
            ),
            normalized_record_id=str(
                record.normalized_record_id
            ),
            evidence_type=(
                self.EVIDENCE_TYPE
            ),
            correlation_rule=(
                self.CORRELATION_RULE
            ),
            observed_at=record.normalized_at,
            last_observed_at=(
                record.normalized_at
            ),
            source_published_at=(
                source_published_at
            ),
            correlation_confidence=1.0,
        )

        return CanonicalVulnerabilityObservation(
            identifiers=(
                identifier,
            ),
            evidence=evidence,
            suggested_status="active",
        )