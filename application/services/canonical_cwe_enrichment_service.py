from __future__ import annotations

from collections.abc import (
    Iterable,
    Sequence,
)
from dataclasses import dataclass
from typing import TypeAlias
from uuid import UUID

from application.models.cisa_kev_canonical_source_record import (
    CisaKevCanonicalSourceRecord,
)
from application.models.github_advisory_canonical_source_record import (
    GitHubAdvisoryCanonicalSourceRecord,
)
from application.ports.outbound.canonical_cwe_enrichment_unit_of_work import (
    CanonicalCWEEnrichmentUnitOfWork,
)
from application.services.canonical_cwe_association_builder import (
    CanonicalCWEAssociationBuilder,
)
from application.services.cwe_lookup_service import (
    CWELookupService,
)
from domain.canonical_vulnerability import (
    CanonicalVulnerability,
)
from domain.canonical_vulnerability_weakness import (
    CanonicalVulnerabilityWeakness,
)


CanonicalCWESourceRecord: TypeAlias = (
    GitHubAdvisoryCanonicalSourceRecord
    | CisaKevCanonicalSourceRecord
)

_EvidenceKey: TypeAlias = tuple[str, str]


class CanonicalCWEEnrichmentError(
    RuntimeError
):
    """
    Erreur générique de l'enrichissement canonique CWE.
    """


class CanonicalCWEEnrichmentResolutionError(
    CanonicalCWEEnrichmentError
):
    """
    Une source contenant des CWE ne peut pas être reliée
    à une vulnérabilité canonique exploitable.
    """


class CanonicalCWEEnrichmentConflictError(
    CanonicalCWEEnrichmentError
):
    """
    Une même preuve exacte est associée à plusieurs
    vulnérabilités canoniques.
    """


@dataclass(
    frozen=True,
    slots=True,
)
class CanonicalCWEEnrichmentResult:
    records_received: int
    records_with_cwe_references: int
    records_enriched: int
    records_without_catalogued_cwe: int

    requested_unique_cwe_ids: int
    found_unique_cwe_ids: int

    missing_cwe_ids: tuple[str, ...]

    association_candidates: int
    unique_associations: int
    persisted: int


class CanonicalCWEEnrichmentService:
    """
    Enrichit des vulnérabilités canoniques avec les CWE
    provenant des projections normalisées.

    Le service réalise au maximum :
    - une consultation groupée du catalogue CWE ;
    - aucune recherche SQL de vulnérabilité canonique ;
    - un seul upsert groupé d'associations ;
    - un seul commit d'écriture.

    Les vulnérabilités sont résolues en mémoire à partir
    des preuves exactes déjà retournées par le service
    de corrélation canonique.
    """

    DEFAULT_MAX_RECORDS = 5_000

    TERMINAL_STATUSES = frozenset(
        {
            "withdrawn",
            "rejected",
            "merged",
        }
    )

    def __init__(
        self,
        *,
        cwe_lookup: CWELookupService,
        builder: CanonicalCWEAssociationBuilder,
        unit_of_work: (
            CanonicalCWEEnrichmentUnitOfWork
        ),
        max_records: int = DEFAULT_MAX_RECORDS,
    ) -> None:
        if cwe_lookup is None:
            raise ValueError(
                "cwe_lookup must not be None"
            )

        if builder is None:
            raise ValueError(
                "builder must not be None"
            )

        if unit_of_work is None:
            raise ValueError(
                "unit_of_work must not be None"
            )

        if (
            isinstance(max_records, bool)
            or not isinstance(
                max_records,
                int,
            )
        ):
            raise TypeError(
                "max_records must be an integer"
            )

        if max_records < 1:
            raise ValueError(
                "max_records must be "
                "greater than zero"
            )

        self._cwe_lookup = cwe_lookup
        self._builder = builder
        self._unit_of_work = unit_of_work
        self._max_records = max_records

    def enrich(
        self,
        *,
        records: Iterable[
            CanonicalCWESourceRecord
        ],
        aggregates: Iterable[
            CanonicalVulnerability
        ],
    ) -> CanonicalCWEEnrichmentResult:
        """
        Valide et persiste les associations CWE d'un lot.

        Le lot peut contenir des projections GitHub Advisory,
        CISA KEV ou un mélange des deux.
        """
        normalized_records = (
            self._normalize_records(
                records
            )
        )

        normalized_aggregates = (
            self._normalize_aggregates(
                aggregates
            )
        )

        records_with_cwe_references = sum(
            bool(
                self._record_cwe_ids(
                    record
                )
            )
            for record in normalized_records
        )

        requested_cwe_ids = (
            self._collect_requested_cwe_ids(
                normalized_records
            )
        )

        if not requested_cwe_ids:
            return CanonicalCWEEnrichmentResult(
                records_received=len(
                    normalized_records
                ),
                records_with_cwe_references=0,
                records_enriched=0,
                records_without_catalogued_cwe=0,
                requested_unique_cwe_ids=0,
                found_unique_cwe_ids=0,
                missing_cwe_ids=(),
                association_candidates=0,
                unique_associations=0,
                persisted=0,
            )

        official_weaknesses = (
            self._cwe_lookup
            .find_many_by_cwe_ids(
                requested_cwe_ids
            )
        )

        official_cwe_ids = (
            self._validate_lookup_result(
                requested_cwe_ids=(
                    requested_cwe_ids
                ),
                result=official_weaknesses,
            )
        )

        missing_cwe_ids = tuple(
            cwe_id
            for cwe_id in requested_cwe_ids
            if cwe_id not in official_cwe_ids
        )

        matching_cwe_ids_by_record: list[
            tuple[str, ...]
        ] = []

        required_evidence_keys: set[
            _EvidenceKey
        ] = set()

        records_without_catalogued_cwe = 0

        for record in normalized_records:
            source_cwe_ids = (
                self._record_cwe_ids(
                    record
                )
            )

            matching_cwe_ids = tuple(
                cwe_id
                for cwe_id in source_cwe_ids
                if cwe_id in official_cwe_ids
            )

            matching_cwe_ids_by_record.append(
                matching_cwe_ids
            )

            if (
                source_cwe_ids
                and not matching_cwe_ids
            ):
                records_without_catalogued_cwe += 1

            if matching_cwe_ids:
                required_evidence_keys.add(
                    self._record_evidence_key(
                        record
                    )
                )

        if not required_evidence_keys:
            return CanonicalCWEEnrichmentResult(
                records_received=len(
                    normalized_records
                ),
                records_with_cwe_references=(
                    records_with_cwe_references
                ),
                records_enriched=0,
                records_without_catalogued_cwe=(
                    records_without_catalogued_cwe
                ),
                requested_unique_cwe_ids=len(
                    requested_cwe_ids
                ),
                found_unique_cwe_ids=len(
                    official_cwe_ids
                ),
                missing_cwe_ids=missing_cwe_ids,
                association_candidates=0,
                unique_associations=0,
                persisted=0,
            )

        owners_by_evidence = (
            self._index_aggregate_owners(
                aggregates=(
                    normalized_aggregates
                ),
                required_evidence_keys=(
                    frozenset(
                        required_evidence_keys
                    )
                ),
            )
        )

        association_candidates: list[
            CanonicalVulnerabilityWeakness
        ] = []

        records_enriched = 0

        for (
            record,
            matching_cwe_ids,
        ) in zip(
            normalized_records,
            matching_cwe_ids_by_record,
            strict=True,
        ):
            if not matching_cwe_ids:
                continue

            evidence_key = (
                self._record_evidence_key(
                    record
                )
            )

            vulnerability_id = (
                owners_by_evidence.get(
                    evidence_key
                )
            )

            if vulnerability_id is None:
                raise (
                    CanonicalCWEEnrichmentResolutionError(
                        "A source record containing "
                        "catalogued CWE identifiers "
                        "does not resolve to a canonical "
                        "vulnerability"
                    )
                )

            associations = (
                self._build_associations(
                    record=record,
                    vulnerability_id=(
                        vulnerability_id
                    ),
                    official_cwe_ids=(
                        matching_cwe_ids
                    ),
                )
            )

            if len(associations) != len(
                matching_cwe_ids
            ):
                raise CanonicalCWEEnrichmentError(
                    "CWE association builder returned "
                    "an unexpected association count"
                )

            association_candidates.extend(
                associations
            )

            records_enriched += 1

        unique_association_count = len(
            {
                association.key
                for association
                in association_candidates
            }
        )

        if not association_candidates:
            return CanonicalCWEEnrichmentResult(
                records_received=len(
                    normalized_records
                ),
                records_with_cwe_references=(
                    records_with_cwe_references
                ),
                records_enriched=0,
                records_without_catalogued_cwe=(
                    records_without_catalogued_cwe
                ),
                requested_unique_cwe_ids=len(
                    requested_cwe_ids
                ),
                found_unique_cwe_ids=len(
                    official_cwe_ids
                ),
                missing_cwe_ids=missing_cwe_ids,
                association_candidates=0,
                unique_associations=0,
                persisted=0,
            )

        with self._unit_of_work as unit_of_work:
            persisted_count = (
                unit_of_work
                .canonical_vulnerability_weaknesses
                .upsert_many(
                    association_candidates
                )
            )

            if (
                persisted_count
                != unique_association_count
            ):
                raise CanonicalCWEEnrichmentError(
                    "Canonical CWE repository returned "
                    "an unexpected persisted "
                    "association count"
                )

            unit_of_work.commit()

        return CanonicalCWEEnrichmentResult(
            records_received=len(
                normalized_records
            ),
            records_with_cwe_references=(
                records_with_cwe_references
            ),
            records_enriched=records_enriched,
            records_without_catalogued_cwe=(
                records_without_catalogued_cwe
            ),
            requested_unique_cwe_ids=len(
                requested_cwe_ids
            ),
            found_unique_cwe_ids=len(
                official_cwe_ids
            ),
            missing_cwe_ids=missing_cwe_ids,
            association_candidates=len(
                association_candidates
            ),
            unique_associations=(
                unique_association_count
            ),
            persisted=persisted_count,
        )

    def _normalize_records(
        self,
        values: Iterable[
            CanonicalCWESourceRecord
        ],
    ) -> list[
        CanonicalCWESourceRecord
    ]:
        if isinstance(
            values,
            (str, bytes),
        ):
            raise TypeError(
                "records must be an iterable "
                "of canonical CWE source records"
            )

        try:
            iterator = iter(
                values
            )
        except TypeError as error:
            raise TypeError(
                "records must be iterable"
            ) from error

        normalized_values: list[
            CanonicalCWESourceRecord
        ] = []

        for value in iterator:
            if not isinstance(
                value,
                (
                    GitHubAdvisoryCanonicalSourceRecord,
                    CisaKevCanonicalSourceRecord,
                ),
            ):
                raise TypeError(
                    "Every record must be a GitHub "
                    "Advisory or CISA KEV canonical "
                    "source record"
                )

            normalized_values.append(
                value
            )

            if (
                len(normalized_values)
                > self._max_records
            ):
                raise ValueError(
                    "records exceeds the configured "
                    f"limit of {self._max_records}"
                )

        return normalized_values

    def _normalize_aggregates(
        self,
        values: Iterable[
            CanonicalVulnerability
        ],
    ) -> list[
        CanonicalVulnerability
    ]:
        if isinstance(
            values,
            (str, bytes),
        ):
            raise TypeError(
                "aggregates must be an iterable "
                "of CanonicalVulnerability"
            )

        try:
            iterator = iter(
                values
            )
        except TypeError as error:
            raise TypeError(
                "aggregates must be iterable"
            ) from error

        normalized_values: list[
            CanonicalVulnerability
        ] = []

        for value in iterator:
            if not isinstance(
                value,
                CanonicalVulnerability,
            ):
                raise TypeError(
                    "Every aggregate must be a "
                    "CanonicalVulnerability"
                )

            normalized_values.append(
                value
            )

            if (
                len(normalized_values)
                > self._max_records
            ):
                raise ValueError(
                    "aggregates exceeds the configured "
                    f"limit of {self._max_records}"
                )

        return normalized_values

    @staticmethod
    def _collect_requested_cwe_ids(
        records: Sequence[
            CanonicalCWESourceRecord
        ],
    ) -> list[str]:
        requested_cwe_ids: list[str] = []
        seen: set[str] = set()

        for record in records:
            for cwe_id in (
                CanonicalCWEEnrichmentService
                ._record_cwe_ids(
                    record
                )
            ):
                if cwe_id in seen:
                    continue

                seen.add(
                    cwe_id
                )

                requested_cwe_ids.append(
                    cwe_id
                )

        return requested_cwe_ids

    @staticmethod
    def _validate_lookup_result(
        *,
        requested_cwe_ids: Sequence[str],
        result: object,
    ) -> frozenset[str]:
        if not isinstance(
            result,
            dict,
        ):
            raise TypeError(
                "cwe lookup result must be a dict"
            )

        requested_cwe_id_set = set(
            requested_cwe_ids
        )

        returned_cwe_ids = set(
            result
        )

        unexpected_cwe_ids = (
            returned_cwe_ids
            - requested_cwe_id_set
        )

        if unexpected_cwe_ids:
            raise CanonicalCWEEnrichmentError(
                "CWE lookup returned unexpected "
                "identifiers"
            )

        return frozenset(
            returned_cwe_ids
        )

    @classmethod
    def _index_aggregate_owners(
        cls,
        *,
        aggregates: Sequence[
            CanonicalVulnerability
        ],
        required_evidence_keys: frozenset[
            _EvidenceKey
        ],
    ) -> dict[
        _EvidenceKey,
        UUID,
    ]:
        owners: dict[
            _EvidenceKey,
            UUID,
        ] = {}

        aggregates_by_id: dict[
            UUID,
            CanonicalVulnerability,
        ] = {}

        for aggregate in aggregates:
            previous_snapshot = (
                aggregates_by_id.get(
                    aggregate.id
                )
            )

            if (
                previous_snapshot is not None
                and previous_snapshot != aggregate
            ):
                raise (
                    CanonicalCWEEnrichmentConflictError(
                        "Several inconsistent snapshots "
                        "were provided for one canonical "
                        "vulnerability"
                    )
                )

            aggregates_by_id[
                aggregate.id
            ] = aggregate

            for evidence in aggregate.evidences:
                evidence_key = evidence.key

                if (
                    evidence_key
                    not in required_evidence_keys
                ):
                    continue

                if (
                    aggregate.status
                    in cls.TERMINAL_STATUSES
                ):
                    raise (
                        CanonicalCWEEnrichmentResolutionError(
                            "A terminal canonical "
                            "vulnerability cannot receive "
                            "new CWE associations"
                        )
                    )

                existing_owner = owners.get(
                    evidence_key
                )

                if (
                    existing_owner is not None
                    and existing_owner
                    != aggregate.id
                ):
                    raise (
                        CanonicalCWEEnrichmentConflictError(
                            "An exact source evidence "
                            "belongs to several canonical "
                            "vulnerabilities"
                        )
                    )

                owners[
                    evidence_key
                ] = aggregate.id

        return owners

    def _build_associations(
        self,
        *,
        record: CanonicalCWESourceRecord,
        vulnerability_id: UUID,
        official_cwe_ids: tuple[str, ...],
    ) -> tuple[
        CanonicalVulnerabilityWeakness,
        ...,
    ]:
        if isinstance(
            record,
            GitHubAdvisoryCanonicalSourceRecord,
        ):
            return (
                self._builder
                .build_for_github_advisory(
                    record=record,
                    vulnerability_id=(
                        vulnerability_id
                    ),
                    official_cwe_ids=(
                        official_cwe_ids
                    ),
                )
            )

        return (
            self._builder
            .build_for_cisa_kev(
                record=record,
                vulnerability_id=(
                    vulnerability_id
                ),
                official_cwe_ids=(
                    official_cwe_ids
                ),
            )
        )

    @staticmethod
    def _record_cwe_ids(
        record: CanonicalCWESourceRecord,
    ) -> tuple[str, ...]:
        return record.cwe_ids

    @staticmethod
    def _record_evidence_key(
        record: CanonicalCWESourceRecord,
    ) -> _EvidenceKey:
        if isinstance(
            record,
            GitHubAdvisoryCanonicalSourceRecord,
        ):
            return (
                CanonicalCWEAssociationBuilder
                .GITHUB_SOURCE,
                record.ghsa_id,
            )

        return (
            CanonicalCWEAssociationBuilder
            .CISA_KEV_SOURCE,
            record.cve_id,
        )