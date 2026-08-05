from __future__ import annotations

from dataclasses import dataclass

from application.models.urlhaus_canonical_source_record import (
    URLhausCanonicalCursor,
)
from application.ports.outbound.urlhaus_canonical_source import (
    URLhausCanonicalSource,
)
from application.services.canonical_web_indicator_correlation_service import (
    CanonicalWebCorrelationResult,
    CanonicalWebIndicatorCorrelationService,
)
from application.services.urlhaus_canonical_observation_builder import (
    URLhausCanonicalObservationBuilder,
)


@dataclass(
    frozen=True,
    slots=True,
)
class URLhausCanonicalCorrelationBatchResult:
    records_read: int

    next_cursor: (
        URLhausCanonicalCursor
        | None
    )

    source_exhausted: bool

    correlation: CanonicalWebCorrelationResult


class URLhausCanonicalCorrelationBatchService:
    """
    Orchestre un lot URLhaus normalisé vers la couche
    canonique Web.
    """

    DEFAULT_BATCH_SIZE = 500
    MAX_BATCH_SIZE = 1_000

    def __init__(
        self,
        *,
        source: URLhausCanonicalSource,
        builder: (
            URLhausCanonicalObservationBuilder
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
            URLhausCanonicalCursor
            | None
        ) = None,
        limit: int = DEFAULT_BATCH_SIZE,
    ) -> (
        URLhausCanonicalCorrelationBatchResult
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
                "URLhaus canonical source "
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
            URLhausCanonicalCorrelationBatchResult(
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