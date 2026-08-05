from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Protocol

from application.models.cisa_kev_canonical_source_record import (
    CisaKevCanonicalCursor,
)
from application.services.cisa_kev_canonical_correlation_batch_service import (
    CisaKevCanonicalCorrelationBatchResult,
)


_URL_CREDENTIALS_PATTERN = re.compile(
    r"([a-z][a-z0-9+.-]*://)"
    r"([^/\s:@]+):([^@/\s]+)@",
    flags=re.IGNORECASE,
)

_SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"\b("
    r"password|passwd|pwd|token|"
    r"api[_-]?key|secret|authorization"
    r")\b"
    r"\s*[:=]\s*"
    r"(?:bearer\s+)?"
    r"[^\s,;]+",
    flags=re.IGNORECASE,
)

_BEARER_TOKEN_PATTERN = re.compile(
    r"\bbearer\s+[a-z0-9._~+/=-]+",
    flags=re.IGNORECASE,
)

_CONTROL_CHARACTER_PATTERN = re.compile(
    r"[\x00-\x1f\x7f]+"
)


class CisaKevCanonicalBatchProcessor(
    Protocol
):
    """
    Port minimal utilisé par le job CISA KEV.

    L'implémentation SQLAlchemy ouvrira une session courte
    pour chaque appel à process_batch().
    """

    def process_batch(
        self,
        *,
        after_cursor: (
            CisaKevCanonicalCursor
            | None
        ) = None,
        limit: int,
    ) -> (
        CisaKevCanonicalCorrelationBatchResult
    ):
        ...


@dataclass(
    frozen=True,
    slots=True,
)
class CisaKevCanonicalCorrelationJobResult:
    batches_processed: int
    records_read: int

    source_exhausted: bool
    max_batches_reached: bool

    next_cursor: (
        CisaKevCanonicalCursor
        | None
    )

    observations_received: int
    components_built: int
    canonical_created: int
    canonical_updated: int
    canonical_persisted: int

    cwe_records_received: int
    cwe_records_with_references: int
    cwe_records_enriched: int
    cwe_records_without_catalogued_cwe: int
    cwe_association_candidates: int
    cwe_unique_associations: int
    cwe_persisted: int


@dataclass(
    slots=True,
)
class _CisaKevJobCounters:
    batches_processed: int = 0
    records_read: int = 0

    observations_received: int = 0
    components_built: int = 0
    canonical_created: int = 0
    canonical_updated: int = 0
    canonical_persisted: int = 0

    cwe_records_received: int = 0
    cwe_records_with_references: int = 0
    cwe_records_enriched: int = 0
    cwe_records_without_catalogued_cwe: int = 0
    cwe_association_candidates: int = 0
    cwe_unique_associations: int = 0
    cwe_persisted: int = 0

    def add(
        self,
        result: (
            CisaKevCanonicalCorrelationBatchResult
        ),
    ) -> None:
        self.batches_processed += 1
        self.records_read += result.records_read

        correlation = result.correlation

        self.observations_received += (
            correlation.observations_received
        )
        self.components_built += (
            correlation.components_built
        )
        self.canonical_created += (
            correlation.created
        )
        self.canonical_updated += (
            correlation.updated
        )
        self.canonical_persisted += (
            correlation.persisted
        )

        enrichment = result.cwe_enrichment

        self.cwe_records_received += (
            enrichment.records_received
        )
        self.cwe_records_with_references += (
            enrichment.records_with_cwe_references
        )
        self.cwe_records_enriched += (
            enrichment.records_enriched
        )
        self.cwe_records_without_catalogued_cwe += (
            enrichment.records_without_catalogued_cwe
        )
        self.cwe_association_candidates += (
            enrichment.association_candidates
        )
        self.cwe_unique_associations += (
            enrichment.unique_associations
        )
        self.cwe_persisted += (
            enrichment.persisted
        )


class CisaKevCanonicalCorrelationJob:
    """
    Enchaîne les lots canoniques CISA KEV.

    Le job ne conserve aucune session SQLAlchemy et ne stocke
    pas les résultats individuels des lots en mémoire.

    La progression durable du curseur reste volontairement
    hors de cette classe.
    """

    DEFAULT_BATCH_SIZE = 500
    MAX_BATCH_SIZE = 1_000

    DEFAULT_MAX_BATCHES = 10_000

    MAX_LOG_SUMMARY_LENGTH = 1_000

    def __init__(
        self,
        *,
        processor: CisaKevCanonicalBatchProcessor,
        batch_size: int = DEFAULT_BATCH_SIZE,
        max_batches: int = DEFAULT_MAX_BATCHES,
        logger: logging.Logger | None = None,
    ) -> None:
        if processor is None:
            raise ValueError(
                "processor must not be None"
            )

        self._processor = processor
        self._batch_size = (
            self._validate_batch_size(
                batch_size
            )
        )
        self._max_batches = (
            self._validate_max_batches(
                max_batches
            )
        )
        self._logger = (
            logging.getLogger(__name__)
            if logger is None
            else logger
        )

    def run(
        self,
        *,
        after_cursor: (
            CisaKevCanonicalCursor
            | None
        ) = None,
    ) -> (
        CisaKevCanonicalCorrelationJobResult
    ):
        counters = _CisaKevJobCounters()
        current_cursor = after_cursor

        try:
            for _ in range(
                self._max_batches
            ):
                batch_result = (
                    self._processor.process_batch(
                        after_cursor=current_cursor,
                        limit=self._batch_size,
                    )
                )

                self._validate_batch_result(
                    batch_result
                )

                counters.add(
                    batch_result
                )

                next_cursor = (
                    batch_result.next_cursor
                )

                if batch_result.source_exhausted:
                    return self._build_result(
                        counters=counters,
                        next_cursor=next_cursor,
                        source_exhausted=True,
                        max_batches_reached=False,
                    )

                if batch_result.records_read == 0:
                    raise RuntimeError(
                        "CISA KEV canonical processor "
                        "returned an empty "
                        "non-exhausted batch"
                    )

                if next_cursor is None:
                    raise RuntimeError(
                        "CISA KEV canonical pagination "
                        "did not return a next cursor"
                    )

                if next_cursor == current_cursor:
                    raise RuntimeError(
                        "CISA KEV canonical pagination "
                        "cursor did not progress"
                    )

                current_cursor = next_cursor

            return self._build_result(
                counters=counters,
                next_cursor=current_cursor,
                source_exhausted=False,
                max_batches_reached=True,
            )

        except Exception as error:
            self._logger.error(
                "CISA KEV canonical correlation "
                "job failed: %s",
                self._sanitize_error_summary(
                    error
                ),
            )
            raise

    @classmethod
    def _validate_batch_size(
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
                "batch_size must be an integer"
            )

        if not (
            1
            <= value
            <= cls.MAX_BATCH_SIZE
        ):
            raise ValueError(
                "batch_size must be between 1 "
                f"and {cls.MAX_BATCH_SIZE}"
            )

        return value

    @staticmethod
    def _validate_max_batches(
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
                "max_batches must be an integer"
            )

        if value < 1:
            raise ValueError(
                "max_batches must be greater "
                "than zero"
            )

        return value

    @staticmethod
    def _validate_batch_result(
        result: (
            CisaKevCanonicalCorrelationBatchResult
        ),
    ) -> None:
        records_read = result.records_read

        if (
            isinstance(records_read, bool)
            or not isinstance(
                records_read,
                int,
            )
            or records_read < 0
        ):
            raise RuntimeError(
                "CISA KEV canonical processor "
                "returned an invalid "
                "records_read value"
            )

        if not isinstance(
            result.source_exhausted,
            bool,
        ):
            raise RuntimeError(
                "CISA KEV canonical processor "
                "returned an invalid "
                "source_exhausted value"
            )

    @staticmethod
    def _build_result(
        *,
        counters: _CisaKevJobCounters,
        next_cursor: (
            CisaKevCanonicalCursor
            | None
        ),
        source_exhausted: bool,
        max_batches_reached: bool,
    ) -> (
        CisaKevCanonicalCorrelationJobResult
    ):
        return (
            CisaKevCanonicalCorrelationJobResult(
                batches_processed=(
                    counters.batches_processed
                ),
                records_read=(
                    counters.records_read
                ),
                source_exhausted=(
                    source_exhausted
                ),
                max_batches_reached=(
                    max_batches_reached
                ),
                next_cursor=next_cursor,
                observations_received=(
                    counters.observations_received
                ),
                components_built=(
                    counters.components_built
                ),
                canonical_created=(
                    counters.canonical_created
                ),
                canonical_updated=(
                    counters.canonical_updated
                ),
                canonical_persisted=(
                    counters.canonical_persisted
                ),
                cwe_records_received=(
                    counters.cwe_records_received
                ),
                cwe_records_with_references=(
                    counters
                    .cwe_records_with_references
                ),
                cwe_records_enriched=(
                    counters.cwe_records_enriched
                ),
                cwe_records_without_catalogued_cwe=(
                    counters
                    .cwe_records_without_catalogued_cwe
                ),
                cwe_association_candidates=(
                    counters
                    .cwe_association_candidates
                ),
                cwe_unique_associations=(
                    counters
                    .cwe_unique_associations
                ),
                cwe_persisted=(
                    counters.cwe_persisted
                ),
            )
        )

    @classmethod
    def _sanitize_error_summary(
        cls,
        error: Exception,
    ) -> str:
        summary = (
            f"{type(error).__name__}: "
            f"{error}"
        )

        summary = (
            _CONTROL_CHARACTER_PATTERN.sub(
                " ",
                summary,
            )
        )

        summary = (
            _URL_CREDENTIALS_PATTERN.sub(
                r"\1***:***@",
                summary,
            )
        )

        summary = (
            _SECRET_ASSIGNMENT_PATTERN.sub(
                lambda match: (
                    f"{match.group(1)}=***"
                ),
                summary,
            )
        )

        summary = (
            _BEARER_TOKEN_PATTERN.sub(
                "Bearer ***",
                summary,
            )
        )

        return summary[
            :cls.MAX_LOG_SUMMARY_LENGTH
        ]