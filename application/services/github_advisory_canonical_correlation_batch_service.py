from __future__ import annotations

from dataclasses import dataclass

from application.models.github_advisory_canonical_source_record import (
    GitHubAdvisoryCanonicalCursor,
)
from application.ports.outbound.github_advisory_canonical_source import (
    GitHubAdvisoryCanonicalSource,
)
from application.services.canonical_vulnerability_correlation_service import (
    CanonicalCorrelationResult,
    CanonicalVulnerabilityCorrelationService,
)
from application.services.github_advisory_canonical_observation_builder import (
    GitHubAdvisoryCanonicalObservationBuilder,
)


@dataclass(
    frozen=True,
    slots=True,
)
class GitHubAdvisoryCanonicalCorrelationBatchResult:
    records_read: int
    next_cursor: (
        GitHubAdvisoryCanonicalCursor
        | None
    )
    source_exhausted: bool
    correlation: CanonicalCorrelationResult


class GitHubAdvisoryCanonicalCorrelationBatchService:
    """
    Orchestre un lot d'advisories GitHub normalisés
    vers la couche canonique.

    Le reader filtre les advisories retirés et le
    service canonique gère une transaction par lot.
    """

    DEFAULT_BATCH_SIZE = 500
    MAX_BATCH_SIZE = 1_000

    def __init__(
        self,
        *,
        source: GitHubAdvisoryCanonicalSource,
        builder: (
            GitHubAdvisoryCanonicalObservationBuilder
        ),
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
            GitHubAdvisoryCanonicalCursor
            | None
        ) = None,
        limit: int = DEFAULT_BATCH_SIZE,
    ) -> (
        GitHubAdvisoryCanonicalCorrelationBatchResult
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
                "GitHub advisory canonical source "
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

        return (
            GitHubAdvisoryCanonicalCorrelationBatchResult(
                records_read=len(records),
                next_cursor=next_cursor,
                source_exhausted=(
                    len(records)
                    < normalized_limit
                ),
                correlation=correlation_result,
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