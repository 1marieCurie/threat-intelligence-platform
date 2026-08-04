from __future__ import annotations

from application.models.canonical_vulnerability_observation import (
    CanonicalVulnerabilityObservation,
)
from application.models.github_advisory_canonical_source_record import (
    GitHubAdvisoryCanonicalSourceRecord,
)
from domain.vulnerability_evidence import (
    VulnerabilityEvidence,
)
from domain.vulnerability_identifier import (
    VulnerabilityIdentifier,
)


class GitHubAdvisoryCanonicalObservationError(
    ValueError
):
    """
    Erreur de transformation d'un advisory normalisé
    en observation canonique.
    """


class GitHubAdvisoryCanonicalObservationBuilder:
    """
    Construit une observation canonique depuis un
    GitHub Security Advisory normalisé.

    Un advisory GitHub ne prouve pas une exploitation
    active. Il propose donc le statut provisional.

    Les advisories retirés sont refusés tant que la
    transition canonique vers withdrawn n'est pas
    explicitement prise en charge.
    """

    SOURCE = "github_advisory"
    EVIDENCE_TYPE = "github_security_advisory"

    EXACT_GHSA_RULE = "exact_ghsa"
    EXACT_CVE_GHSA_RULE = "exact_cve_ghsa"

    def build(
        self,
        *,
        record: GitHubAdvisoryCanonicalSourceRecord,
    ) -> CanonicalVulnerabilityObservation:
        if not isinstance(
            record,
            GitHubAdvisoryCanonicalSourceRecord,
        ):
            raise TypeError(
                "record must be a "
                "GitHubAdvisoryCanonicalSourceRecord"
            )

        if record.is_withdrawn:
            raise (
                GitHubAdvisoryCanonicalObservationError(
                    "Withdrawn GitHub advisories "
                    "cannot produce a provisional "
                    "canonical observation"
                )
            )

        identifiers = self._build_identifiers(
            record
        )

        correlation_rule = (
            self.EXACT_CVE_GHSA_RULE
            if record.cve_id is not None
            else self.EXACT_GHSA_RULE
        )

        evidence = VulnerabilityEvidence(
            source=self.SOURCE,
            source_record_key=record.ghsa_id,
            normalized_record_id=str(
                record.normalized_record_id
            ),
            evidence_type=(
                self.EVIDENCE_TYPE
            ),
            correlation_rule=(
                correlation_rule
            ),
            observed_at=record.normalized_at,
            last_observed_at=(
                record.normalized_at
            ),
            source_published_at=(
                record.published_at
            ),
            source_modified_at=(
                record.updated_at
            ),
            correlation_confidence=1.0,
        )

        return CanonicalVulnerabilityObservation(
            identifiers=identifiers,
            evidence=evidence,
            suggested_status="provisional",
        )

    @staticmethod
    def _build_identifiers(
        record: GitHubAdvisoryCanonicalSourceRecord,
    ) -> tuple[
        VulnerabilityIdentifier,
        ...,
    ]:
        if record.cve_id is None:
            return (
                VulnerabilityIdentifier(
                    namespace="GHSA",
                    value=record.ghsa_id,
                    is_primary=True,
                ),
            )

        return (
            VulnerabilityIdentifier(
                namespace="CVE",
                value=record.cve_id,
                is_primary=True,
            ),
            VulnerabilityIdentifier(
                namespace="GHSA",
                value=record.ghsa_id,
                is_primary=False,
            ),
        )