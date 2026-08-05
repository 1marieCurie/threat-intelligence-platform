from __future__ import annotations

from dataclasses import dataclass

from application.models.phishtank_canonical_source_record import (
    PhishTankCanonicalCursor,
)
from application.ports.outbound.phishtank_canonical_source import (
    PhishTankCanonicalSource,
)
from application.services.canonical_web_indicator_correlation_service import (
    CanonicalWebCorrelationResult,
    CanonicalWebIndicatorCorrelationService,
)
from application.services.phishtank_canonical_observation_builder import (
    PhishTankCanonicalObservationBuilder,
)


@dataclass(
    frozen=True,
    slots=True,
)
class PhishTankCanonicalCorrelationBatchResult:
    records_read: int

    next_cursor: (
        PhishTankCanonicalCursor
        | None
    )

    source_exhausted: bool

    correlation: CanonicalWebCorrelationResult


class PhishTankCanonicalCorrelationBatchService:
    """
    Orchestre un lot PhishTank normalisé vers la couche
    canonique Web.

    Le curseur retourné ne doit être sauvegardé qu'après
    le retour réussi de cette méthode.
    """

    DEFAULT_BATCH_SIZE = 500
    MAX_BATCH_SIZE = 1_000

    def __init__(
        self,
        *,
        source: PhishTankCanonicalSource,
        builder: (
            PhishTankCanonicalObservationBuilder
        ),
        correlation_service: (
            CanonicalWebIndicatorCorrelationService
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
            PhishTankCanonicalCursor
            | None
        ) = None,
        limit: int = DEFAULT_BATCH_SIZE,
    ) -> (
        PhishTankCanonicalCorrelationBatchResult
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
                "PhishTank canonical source "
                "returned more records "
                "than requested"
            )

        observations = tuple(
            self._builder.build(
                record=record
            )
            for record in records
        )

        correlation = (
            self._correlation_service
            .correlate(
                observations
            )
        )

        return (
            PhishTankCanonicalCorrelationBatchResult(
                records_read=len(records),
                next_cursor=(
                    records[-1].cursor
                    if records
                    else None
                ),
                source_exhausted=(
                    len(records)
                    < normalized_limit
                ),
                correlation=correlation,
            )
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