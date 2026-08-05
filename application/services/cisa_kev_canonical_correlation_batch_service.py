from __future__ import annotations

from dataclasses import dataclass

from application.models.cisa_kev_canonical_source_record import (
    CisaKevCanonicalCursor,
)
from application.ports.outbound.cisa_kev_canonical_source import (
    CisaKevCanonicalSource,
)
from application.services.canonical_cwe_enrichment_service import (
    CanonicalCWEEnrichmentResult,
    CanonicalCWEEnrichmentService,
)
from application.services.canonical_vulnerability_correlation_service import (
    CanonicalCorrelationResult,
    CanonicalVulnerabilityCorrelationService,
)
from application.services.cisa_kev_canonical_observation_builder import (
    CisaKevCanonicalObservationBuilder,
)


@dataclass(
    frozen=True,
    slots=True,
)
class CisaKevCanonicalCorrelationBatchResult:
    """
    Résultat du traitement canonique d'un lot CISA KEV.

    Le curseur ne doit être sauvegardé par l'appelant
    qu'après le retour réussi de process_batch().
    """

    records_read: int

    next_cursor: (
        CisaKevCanonicalCursor
        | None
    )

    source_exhausted: bool

    correlation: CanonicalCorrelationResult

    cwe_enrichment: (
        CanonicalCWEEnrichmentResult
    )


class CisaKevCanonicalCorrelationBatchService:
    """
    Orchestre les lignes CISA KEV normalisées vers
    la couche canonique.

    Étapes :
    - lecture keyset d'un lot normalisé ;
    - construction des observations canoniques ;
    - corrélation exacte par CVE ;
    - enrichissement relationnel CWE ;
    - retour du curseur après réussite complète.

    Le service :
    - ne lit aucun payload brut ;
    - ne conserve aucun état de pagination ;
    - utilise des opérations groupées et bornées ;
    - permet un rejeu idempotent du lot.
    """

    DEFAULT_BATCH_SIZE = 500
    MAX_BATCH_SIZE = 1_000

    def __init__(
        self,
        *,
        source: CisaKevCanonicalSource,
        builder: CisaKevCanonicalObservationBuilder,
        correlation_service: (
            CanonicalVulnerabilityCorrelationService
        ),
        cwe_enrichment_service: (
            CanonicalCWEEnrichmentService
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
                "correlation_service "
                "must not be None"
            )

        if cwe_enrichment_service is None:
            raise ValueError(
                "cwe_enrichment_service "
                "must not be None"
            )

        self._source = source
        self._builder = builder

        self._correlation_service = (
            correlation_service
        )

        self._cwe_enrichment_service = (
            cwe_enrichment_service
        )

    def process_batch(
        self,
        *,
        after_cursor: (
            CisaKevCanonicalCursor
            | None
        ) = None,
        limit: int = DEFAULT_BATCH_SIZE,
    ) -> (
        CisaKevCanonicalCorrelationBatchResult
    ):
        normalized_limit = (
            self._validate_limit(
                limit
            )
        )

        records = self._source.read_batch(
            after_cursor=after_cursor,
            limit=normalized_limit,
        )

        if len(records) > normalized_limit:
            raise RuntimeError(
                "CISA KEV canonical source "
                "returned more records "
                "than requested"
            )

        observations = tuple(
            self._builder.build(
                record=record
            )
            for record in records
        )

        correlation_result = (
            self._correlation_service
            .correlate(
                observations
            )
        )

        cwe_enrichment_result = (
            self._cwe_enrichment_service
            .enrich(
                records=records,
                aggregates=(
                    correlation_result.aggregates
                ),
            )
        )

        next_cursor = (
            records[-1].cursor
            if records
            else None
        )

        return CisaKevCanonicalCorrelationBatchResult(
            records_read=len(records),
            next_cursor=next_cursor,
            source_exhausted=(
                len(records)
                < normalized_limit
            ),
            correlation=correlation_result,
            cwe_enrichment=(
                cwe_enrichment_result
            ),
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