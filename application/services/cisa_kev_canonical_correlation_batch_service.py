from __future__ import annotations

from dataclasses import dataclass

from application.models.cisa_kev_canonical_source_record import (
    CisaKevCanonicalCursor,
)
from application.ports.outbound.cisa_kev_canonical_source import (
    CisaKevCanonicalSource,
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
    Résultat d'un lot de corrélation CISA KEV.

    Le curseur ne doit être sauvegardé par l'appelant
    qu'après le retour réussi de process_batch().
    """

    records_read: int
    next_cursor: CisaKevCanonicalCursor | None
    source_exhausted: bool
    correlation: CanonicalCorrelationResult


class CisaKevCanonicalCorrelationBatchService:
    """
    Orchestre la corrélation des lignes CISA KEV
    normalisées vers la couche canonique.

    Le service :

    - ne lit aucun payload brut ;
    - ne conserve aucun état de pagination ;
    - ne duplique pas la gestion transactionnelle ;
    - traite un nombre borné d'observations.
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

        self._source = source
        self._builder = builder
        self._correlation_service = (
            correlation_service
        )

    def process_batch(
        self,
        *,
        after_cursor: (
            CisaKevCanonicalCursor
            | None
        ) = None,
        limit: int = DEFAULT_BATCH_SIZE,
    ) -> CisaKevCanonicalCorrelationBatchResult:
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