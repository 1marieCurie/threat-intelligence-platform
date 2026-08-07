from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Protocol

from application.services.epss_canonical_correlation_batch_service import (
    EPSSCanonicalCorrelationBatchResult,
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


class EPSSCanonicalBatchProcessor(
    Protocol
):
    """
    Port minimal utilisé par le job EPSS.
    """

    def process_batch(
        self,
        *,
        after_cve_id: str | None = None,
        limit: int,
    ) -> EPSSCanonicalCorrelationBatchResult:
        ...


@dataclass(
    frozen=True,
    slots=True,
)
class EPSSCanonicalCorrelationJobResult:
    batches_processed: int
    records_read: int

    source_exhausted: bool
    max_batches_reached: bool

    next_cve_id: str | None

    observations_received: int
    components_built: int

    canonical_created: int
    canonical_updated: int
    canonical_persisted: int

    epss_records_received: int
    epss_records_matched: int

    epss_records_without_canonical_match: int
    epss_persisted: int


@dataclass(
    slots=True,
)
class _EPSSJobCounters:
    batches_processed: int = 0
    records_read: int = 0

    observations_received: int = 0
    components_built: int = 0

    canonical_created: int = 0
    canonical_updated: int = 0
    canonical_persisted: int = 0

    epss_records_received: int = 0
    epss_records_matched: int = 0

    epss_records_without_canonical_match: int = 0
    epss_persisted: int = 0

    def add(
        self,
        result: EPSSCanonicalCorrelationBatchResult,
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

        enrichment = result.epss_enrichment

        self.epss_records_received += (
            enrichment.records_received
        )

        self.epss_records_matched += (
            enrichment.records_matched
        )

        self.epss_records_without_canonical_match += (
            enrichment
            .records_without_canonical_match
        )

        self.epss_persisted += (
            enrichment.persisted
        )


class EPSSCanonicalCorrelationJob:
    """
    Enchaîne les lots EPSS jusqu'à épuisement
    de normalized.epss_score.

    Le job ne conserve aucune session SQLAlchemy
    entre les lots.

    Le curseur durable reste hors de cette classe.
    """

    DEFAULT_BATCH_SIZE = 500
    MAX_BATCH_SIZE = 1_000

    DEFAULT_MAX_BATCHES = 10_000

    MAX_LOG_SUMMARY_LENGTH = 1_000

    def __init__(
        self,
        *,
        processor: EPSSCanonicalBatchProcessor,
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
        after_cve_id: str | None = None,
    ) -> EPSSCanonicalCorrelationJobResult:
        counters = _EPSSJobCounters()

        current_cursor = after_cve_id

        try:
            for _ in range(
                self._max_batches
            ):
                batch_result = (
                    self._processor.process_batch(
                        after_cve_id=(
                            current_cursor
                        ),
                        limit=self._batch_size,
                    )
                )

                self._validate_batch_result(
                    batch_result
                )

                counters.add(batch_result)

                next_cursor = (
                    batch_result.next_cursor
                )

                if batch_result.source_exhausted:
                    return self._build_result(
                        counters=counters,
                        next_cve_id=next_cursor,
                        source_exhausted=True,
                        max_batches_reached=False,
                    )

                if batch_result.records_read == 0:
                    raise RuntimeError(
                        "EPSS canonical processor "
                        "returned an empty "
                        "non-exhausted batch"
                    )

                if next_cursor is None:
                    raise RuntimeError(
                        "EPSS canonical pagination "
                        "did not return a next cursor"
                    )

                if next_cursor == current_cursor:
                    raise RuntimeError(
                        "EPSS canonical pagination "
                        "cursor did not progress"
                    )

                current_cursor = next_cursor

            return self._build_result(
                counters=counters,
                next_cve_id=current_cursor,
                source_exhausted=False,
                max_batches_reached=True,
            )

        except Exception as error:
            self._logger.error(
                "EPSS canonical correlation "
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
            or not isinstance(value, int)
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
            or not isinstance(value, int)
        ):
            raise TypeError(
                "max_batches must be an integer"
            )

        if value < 1:
            raise ValueError(
                "max_batches must be "
                "greater than zero"
            )

        return value

    @staticmethod
    def _validate_batch_result(
        result: EPSSCanonicalCorrelationBatchResult,
    ) -> None:
        records_read = result.records_read

        if (
            isinstance(records_read, bool)
            or not isinstance(records_read, int)
            or records_read < 0
        ):
            raise RuntimeError(
                "EPSS canonical processor "
                "returned an invalid "
                "records_read value"
            )

        if not isinstance(
            result.source_exhausted,
            bool,
        ):
            raise RuntimeError(
                "EPSS canonical processor "
                "returned an invalid "
                "source_exhausted value"
            )

    @staticmethod
    def _build_result(
        *,
        counters: _EPSSJobCounters,
        next_cve_id: str | None,
        source_exhausted: bool,
        max_batches_reached: bool,
    ) -> EPSSCanonicalCorrelationJobResult:
        return EPSSCanonicalCorrelationJobResult(
            batches_processed=(
                counters.batches_processed
            ),
            records_read=(
                counters.records_read
            ),
            source_exhausted=source_exhausted,
            max_batches_reached=(
                max_batches_reached
            ),
            next_cve_id=next_cve_id,
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
            epss_records_received=(
                counters.epss_records_received
            ),
            epss_records_matched=(
                counters.epss_records_matched
            ),
            epss_records_without_canonical_match=(
                counters
                .epss_records_without_canonical_match
            ),
            epss_persisted=(
                counters.epss_persisted
            ),
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