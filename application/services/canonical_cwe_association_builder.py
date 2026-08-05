from __future__ import annotations

from collections.abc import Iterable
from uuid import UUID

from application.models.cisa_kev_canonical_source_record import (
    CisaKevCanonicalSourceRecord,
)
from application.models.github_advisory_canonical_source_record import (
    GitHubAdvisoryCanonicalSourceRecord,
)
from domain.canonical_vulnerability_weakness import (
    CanonicalVulnerabilityWeakness,
)
from domain.cwe_identifier import (
    normalize_cwe_id,
)


class CanonicalCWEAssociationBuilder:
    """
    Construit les associations canoniques vulnérabilité–CWE.

    Le builder :
    - ne consulte aucun repository ;
    - ne crée aucune entrée du catalogue CWE ;
    - ne participe pas à la corrélation canonique ;
    - ne conserve aucun payload ou texte fournisseur ;
    - produit uniquement des relations CWE validées.

    official_cwe_ids doit provenir de CWELookupService.
    """

    GITHUB_SOURCE = "github_advisory"
    CISA_KEV_SOURCE = "cisa_kev"

    MAX_OFFICIAL_CWE_IDS = 10_000

    def build_for_github_advisory(
        self,
        *,
        record: GitHubAdvisoryCanonicalSourceRecord,
        vulnerability_id: UUID,
        official_cwe_ids: Iterable[str],
    ) -> tuple[
        CanonicalVulnerabilityWeakness,
        ...,
    ]:
        """
        Construit les associations d'un advisory GitHub.

        La clé de provenance utilise le GHSA canonique.
        """
        if not isinstance(
            record,
            GitHubAdvisoryCanonicalSourceRecord,
        ):
            raise TypeError(
                "record must be a "
                "GitHubAdvisoryCanonicalSourceRecord"
            )

        normalized_vulnerability_id = (
            self._validate_vulnerability_id(
                vulnerability_id
            )
        )

        official_cwe_id_set = (
            self._normalize_official_cwe_ids(
                official_cwe_ids
            )
        )

        matching_cwe_ids = (
            self._select_matching_cwe_ids(
                source_cwe_ids=record.cwe_ids,
                official_cwe_ids=(
                    official_cwe_id_set
                ),
            )
        )

        return tuple(
            CanonicalVulnerabilityWeakness(
                vulnerability_id=(
                    normalized_vulnerability_id
                ),
                cwe_id=cwe_id,
                source=self.GITHUB_SOURCE,
                source_record_key=(
                    record.ghsa_id
                ),
                normalized_record_id=str(
                    record.normalized_record_id
                ),
                observed_at=(
                    record.normalized_at
                ),
                last_observed_at=(
                    record.normalized_at
                ),
                source_modified_at=(
                    record.updated_at
                ),
            )
            for cwe_id in matching_cwe_ids
        )

    def build_for_cisa_kev(
        self,
        *,
        record: CisaKevCanonicalSourceRecord,
        vulnerability_id: UUID,
        official_cwe_ids: Iterable[str],
    ) -> tuple[
        CanonicalVulnerabilityWeakness,
        ...,
    ]:
        """
        Construit les associations d'une entrée CISA KEV.

        La clé de provenance utilise le CVE canonique.
        """
        if not isinstance(
            record,
            CisaKevCanonicalSourceRecord,
        ):
            raise TypeError(
                "record must be a "
                "CisaKevCanonicalSourceRecord"
            )

        normalized_vulnerability_id = (
            self._validate_vulnerability_id(
                vulnerability_id
            )
        )

        official_cwe_id_set = (
            self._normalize_official_cwe_ids(
                official_cwe_ids
            )
        )

        matching_cwe_ids = (
            self._select_matching_cwe_ids(
                source_cwe_ids=record.cwe_ids,
                official_cwe_ids=(
                    official_cwe_id_set
                ),
            )
        )

        return tuple(
            CanonicalVulnerabilityWeakness(
                vulnerability_id=(
                    normalized_vulnerability_id
                ),
                cwe_id=cwe_id,
                source=self.CISA_KEV_SOURCE,
                source_record_key=(
                    record.cve_id
                ),
                normalized_record_id=str(
                    record.normalized_record_id
                ),
                observed_at=(
                    record.normalized_at
                ),
                last_observed_at=(
                    record.normalized_at
                ),
                source_modified_at=None,
            )
            for cwe_id in matching_cwe_ids
        )

    @classmethod
    def _normalize_official_cwe_ids(
        cls,
        values: Iterable[str],
    ) -> frozenset[str]:
        """
        Valide strictement les identifiants issus du catalogue.

        Contrairement aux références fournisseur, une valeur officielle
        invalide ou non canonique indique une erreur de programmation
        ou une incohérence du repository.
        """
        if isinstance(
            values,
            (str, bytes),
        ):
            raise TypeError(
                "official_cwe_ids must be an "
                "iterable of canonical identifiers"
            )

        try:
            iterator = iter(
                values
            )
        except TypeError as error:
            raise TypeError(
                "official_cwe_ids must be iterable"
            ) from error

        normalized_values: set[str] = set()

        for value in iterator:
            if not isinstance(
                value,
                str,
            ):
                raise TypeError(
                    "Every official CWE identifier "
                    "must be a string"
                )

            normalized_value = normalize_cwe_id(
                value
            )

            if normalized_value is None:
                raise ValueError(
                    "Every official CWE identifier "
                    "must be valid"
                )

            if value != normalized_value:
                raise ValueError(
                    "Every official CWE identifier "
                    "must already be canonical"
                )

            normalized_values.add(
                normalized_value
            )

            if (
                len(normalized_values)
                > cls.MAX_OFFICIAL_CWE_IDS
            ):
                raise ValueError(
                    "official_cwe_ids exceeds the "
                    "configured limit of "
                    f"{cls.MAX_OFFICIAL_CWE_IDS}"
                )

        return frozenset(
            normalized_values
        )

    @staticmethod
    def _select_matching_cwe_ids(
        *,
        source_cwe_ids: tuple[str, ...],
        official_cwe_ids: frozenset[str],
    ) -> tuple[str, ...]:
        """
        Conserve uniquement les CWE présentes dans la source
        et confirmées par le catalogue officiel.

        L'ordre fournisseur normalisé est conservé.
        """
        return tuple(
            cwe_id
            for cwe_id in source_cwe_ids
            if cwe_id in official_cwe_ids
        )

    @staticmethod
    def _validate_vulnerability_id(
        value: UUID,
    ) -> UUID:
        if not isinstance(
            value,
            UUID,
        ):
            raise TypeError(
                "vulnerability_id must be a UUID"
            )

        if value.int == 0:
            raise ValueError(
                "vulnerability_id must not be nil"
            )

        return value