from __future__ import annotations

from dataclasses import dataclass

from application.ports.outbound.epss_canonical_source import (
    EPSSCanonicalSource,
)
from application.services.canonical_vulnerability_correlation_service import (
    CanonicalCorrelationResult,
    CanonicalVulnerabilityCorrelationService,
)
from application.services.epss_canonical_observation_builder import (
    EPSSCanonicalObservationBuilder,
)


@dataclass(
    frozen=True,
    slots=True,
)
class EPSSCanonicalCorrelationBatchResult:
    """
    Résultat d'un lot de corrélation EPSS.

    next_cursor ne doit être persisté par l'appelant
    qu'après le retour réussi de process_batch().
    """

    records_read: int
    next_cursor: str | None
    source_exhausted: bool
    correlation: CanonicalCorrelationResult


class EPSSCanonicalCorrelationBatchService:
    """
    Orchestre un lot EPSS vers la couche canonique.

    Pipeline :

        normalized.epss_score
        -> projection paginée
        -> observation canonique
        -> corrélation exacte par CVE
        -> transaction canonique unique

    Le service est sans état : le curseur reste sous
    la responsabilité du job ou du scheduler appelant.
    """

    DEFAULT_BATCH_SIZE = 500
    MAX_BATCH_SIZE = 1_000

    def __init__(
        self,
        *,
        source: EPSSCanonicalSource,
        builder: EPSSCanonicalObservationBuilder,
        correlation_service: (
            CanonicalVulnerabilityCorrelationService
        ),
    ) -> None:
        if source is None:
            raise ValueError(
                "source must not be None"
            )

        if builder is None:
            raise ValueError(
                "builder must not be None"
            )

        if correlation_service is None:
            raise ValueError(
                "correlation_service must not be None"
            )

        self._source = source
        self._builder = builder
        self._correlation_service = (
            correlation_service
        )

    def process_batch(
        self,
        *,
        after_cve_id: str | None = None,
        limit: int = DEFAULT_BATCH_SIZE,
    ) -> EPSSCanonicalCorrelationBatchResult:
        normalized_limit = (
            self._validate_limit(
                limit
            )
        )

        records = self._source.read_batch(
            after_cve_id=after_cve_id,
            limit=normalized_limit,
        )

        if len(records) > normalized_limit:
            raise RuntimeError(
                "EPSS canonical source returned "
                "more records than requested"
            )

        observations = tuple(
            self._builder.build(
                cve_id=record.cve_id,
                snapshot=record.snapshot,
                synchronized_at=(
                    record.synchronized_at
                ),
            )
            for record in records
        )

        correlation_result = (
            self._correlation_service
            .correlate(
                observations
            )
        )

        next_cursor = (
            records[-1].cve_id
            if records
            else None
        )

        return EPSSCanonicalCorrelationBatchResult(
            records_read=len(records),
            next_cursor=next_cursor,
            source_exhausted=(
                len(records)
                < normalized_limit
            ),
            correlation=correlation_result,
        )

    @classmethod
    def _validate_limit(
        cls,
        value: int,
    ) -> int:
        if (
            isinstance(value, bool)
            or not isinstance(
                value,
                int,
            )
        ):
            raise TypeError(
                "limit must be an integer"
            )

        if not (
            1
            <= value
            <= cls.MAX_BATCH_SIZE
        ):
            raise ValueError(
                "limit must be between 1 "
                f"and {cls.MAX_BATCH_SIZE}"
            )

        return value