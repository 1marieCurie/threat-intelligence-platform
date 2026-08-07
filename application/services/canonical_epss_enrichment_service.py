from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from application.models.epss_canonical_source_record import (
    EPSSCanonicalSourceRecord,
)
from application.ports.outbound.canonical_vulnerability_epss_repository import (
    CanonicalVulnerabilityEPSSRepository,
)
from domain.canonical_vulnerability import (
    CanonicalVulnerability,
)
from domain.canonical_vulnerability_epss import (
    CanonicalVulnerabilityEPSS,
)


class CanonicalEPSSUnitOfWork(
    Protocol
):
    canonical_vulnerability_epss: (
        CanonicalVulnerabilityEPSSRepository
    )

    def __enter__(
        self,
    ) -> CanonicalEPSSUnitOfWork:
        ...

    def __exit__(
        self,
        exc_type: object,
        exc_value: object,
        traceback: object,
    ) -> None:
        ...

    def commit(
        self,
    ) -> None:
        ...


@dataclass(
    frozen=True,
    slots=True,
)
class CanonicalEPSSEnrichmentResult:
    """
    Métriques de l'enrichissement EPSS d'un lot.
    """

    records_received: int
    canonical_vulnerabilities_received: int

    records_matched: int
    records_without_canonical_match: int

    persisted: int


class CanonicalEPSSEnrichmentService:
    """
    Associe les snapshots EPSS aux vulnérabilités
    canoniques créées ou retrouvées par la corrélation.

    L'absence d'un score EPSS ne provoque aucune
    suppression ni désactivation d'une CVE.
    """

    DEFAULT_MAX_RECORDS = 500
    MAX_RECORDS = 1_000

    def __init__(
        self,
        *,
        unit_of_work: CanonicalEPSSUnitOfWork,
        max_records: int = DEFAULT_MAX_RECORDS,
    ) -> None:
        if unit_of_work is None:
            raise ValueError(
                "unit_of_work must not be None"
            )

        self._unit_of_work = unit_of_work
        self._max_records = (
            self._validate_max_records(
                max_records
            )
        )

    def enrich(
        self,
        *,
        records: tuple[
            EPSSCanonicalSourceRecord,
            ...,
        ],
        aggregates: tuple[
            CanonicalVulnerability,
            ...,
        ],
    ) -> CanonicalEPSSEnrichmentResult:
        normalized_records = (
            self._validate_records(
                records
            )
        )

        normalized_aggregates = (
            self._validate_aggregates(
                aggregates
            )
        )

        vulnerability_ids_by_cve = (
            self._build_vulnerability_ids_by_cve(
                normalized_aggregates
            )
        )

        candidates: list[
            CanonicalVulnerabilityEPSS
        ] = []

        unmatched_records = 0

        for record in normalized_records:
            vulnerability_id = (
                vulnerability_ids_by_cve.get(
                    record.cve_id
                )
            )

            if vulnerability_id is None:
                unmatched_records += 1
                continue

            candidates.append(
                self._build_candidate(
                    record=record,
                    vulnerability_id=(
                        vulnerability_id
                    ),
                )
            )

        if not candidates:
            return CanonicalEPSSEnrichmentResult(
                records_received=(
                    len(normalized_records)
                ),
                canonical_vulnerabilities_received=(
                    len(normalized_aggregates)
                ),
                records_matched=0,
                records_without_canonical_match=(
                    unmatched_records
                ),
                persisted=0,
            )

        with self._unit_of_work as unit_of_work:
            persisted = (
                unit_of_work
                .canonical_vulnerability_epss
                .upsert_many(
                    tuple(candidates)
                )
            )

            unit_of_work.commit()

        return CanonicalEPSSEnrichmentResult(
            records_received=(
                len(normalized_records)
            ),
            canonical_vulnerabilities_received=(
                len(normalized_aggregates)
            ),
            records_matched=len(candidates),
            records_without_canonical_match=(
                unmatched_records
            ),
            persisted=persisted,
        )

    @staticmethod
    def _build_candidate(
        *,
        record: EPSSCanonicalSourceRecord,
        vulnerability_id: UUID,
    ) -> CanonicalVulnerabilityEPSS:
        snapshot = record.snapshot

        return CanonicalVulnerabilityEPSS(
            vulnerability_id=(
                vulnerability_id
            ),
            cve_id=record.cve_id,
            score=snapshot.score,
            percentile=snapshot.percentile,
            score_date=snapshot.score_date,
            api_version=snapshot.api_version,
            synchronized_at=(
                record.synchronized_at
            ),
        )

    @staticmethod
    def _build_vulnerability_ids_by_cve(
        aggregates: tuple[
            CanonicalVulnerability,
            ...,
        ],
    ) -> dict[str, UUID]:
        vulnerability_ids_by_cve: dict[
            str,
            UUID,
        ] = {}

        for aggregate in aggregates:
            for identifier in (
                aggregate.identifiers
            ):
                if (
                    identifier.namespace
                    != "CVE"
                ):
                    continue

                vulnerability_ids_by_cve[
                    identifier.value
                ] = aggregate.id

        return vulnerability_ids_by_cve

    def _validate_records(
        self,
        records: tuple[
            EPSSCanonicalSourceRecord,
            ...,
        ],
    ) -> tuple[
        EPSSCanonicalSourceRecord,
        ...,
    ]:
        if not isinstance(records, tuple):
            raise TypeError(
                "records must be a tuple"
            )

        if len(records) > self._max_records:
            raise ValueError(
                "records exceed max_records"
            )

        for record in records:
            if not isinstance(
                record,
                EPSSCanonicalSourceRecord,
            ):
                raise TypeError(
                    "Every record must be an "
                    "EPSSCanonicalSourceRecord"
                )

        return records

    @staticmethod
    def _validate_aggregates(
        aggregates: tuple[
            CanonicalVulnerability,
            ...,
        ],
    ) -> tuple[
        CanonicalVulnerability,
        ...,
    ]:
        if not isinstance(
            aggregates,
            tuple,
        ):
            raise TypeError(
                "aggregates must be a tuple"
            )

        for aggregate in aggregates:
            if not isinstance(
                aggregate,
                CanonicalVulnerability,
            ):
                raise TypeError(
                    "Every aggregate must be a "
                    "CanonicalVulnerability"
                )

        return aggregates

    @classmethod
    def _validate_max_records(
        cls,
        value: int,
    ) -> int:
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
        ):
            raise TypeError(
                "max_records must be an integer"
            )

        if not (
            1
            <= value
            <= cls.MAX_RECORDS
        ):
            raise ValueError(
                "max_records must be between "
                f"1 and {cls.MAX_RECORDS}"
            )

        return value