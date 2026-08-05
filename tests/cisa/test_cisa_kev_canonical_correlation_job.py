from __future__ import annotations

import logging
from collections import deque
from dataclasses import (
    dataclass,
    field,
)
from types import SimpleNamespace
from typing import cast
from uuid import UUID

import pytest

from application.models.cisa_kev_canonical_source_record import (
    CisaKevCanonicalCursor,
)
from application.services.cisa_kev_canonical_correlation_batch_service import (
    CisaKevCanonicalCorrelationBatchResult,
)
from infrastructure.adapters.inbound.cisa_kev_canonical_correlation_job import (
    CisaKevCanonicalBatchProcessor,
    CisaKevCanonicalCorrelationJob,
)


@dataclass
class FakeCisaKevCanonicalBatchProcessor:
    results: deque[
        CisaKevCanonicalCorrelationBatchResult
    ]

    calls: list[
        tuple[
            CisaKevCanonicalCursor | None,
            int,
        ]
    ] = field(
        default_factory=list
    )

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
        self.calls.append(
            (
                after_cursor,
                limit,
            )
        )

        if not self.results:
            raise AssertionError(
                "No fake batch result remains"
            )

        return self.results.popleft()


class FailingCisaKevCanonicalBatchProcessor:
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
        del after_cursor
        del limit

        raise RuntimeError(
            "postgresql://admin:super-secret@db/test "
            "Authorization: Bearer token-value "
            "password=hunter2"
        )


def _cursor(
    index: int,
) -> CisaKevCanonicalCursor:
    return CisaKevCanonicalCursor(
        cve_id=(
            f"CVE-2026-{1_000 + index}"
        ),
        normalized_record_id=UUID(
            int=index
        ),
    )


def _batch_result(
    *,
    records_read: int,
    next_cursor: (
        CisaKevCanonicalCursor
        | None
    ),
    source_exhausted: bool,
    observations_received: int = 0,
    components_built: int = 0,
    created: int = 0,
    updated: int = 0,
    canonical_persisted: int = 0,
    cwe_records_received: int = 0,
    cwe_records_with_references: int = 0,
    cwe_records_enriched: int = 0,
    cwe_records_without_catalogued_cwe: int = 0,
    association_candidates: int = 0,
    unique_associations: int = 0,
    cwe_persisted: int = 0,
) -> CisaKevCanonicalCorrelationBatchResult:
    correlation = SimpleNamespace(
        observations_received=(
            observations_received
        ),
        components_built=components_built,
        created=created,
        updated=updated,
        persisted=canonical_persisted,
        aggregates=(),
    )

    cwe_enrichment = SimpleNamespace(
        records_received=(
            cwe_records_received
        ),
        records_with_cwe_references=(
            cwe_records_with_references
        ),
        records_enriched=(
            cwe_records_enriched
        ),
        records_without_catalogued_cwe=(
            cwe_records_without_catalogued_cwe
        ),
        requested_unique_cwe_ids=0,
        found_unique_cwe_ids=0,
        missing_cwe_ids=(),
        association_candidates=(
            association_candidates
        ),
        unique_associations=(
            unique_associations
        ),
        persisted=cwe_persisted,
    )

    return cast(
        CisaKevCanonicalCorrelationBatchResult,
        SimpleNamespace(
            records_read=records_read,
            next_cursor=next_cursor,
            source_exhausted=(
                source_exhausted
            ),
            correlation=correlation,
            cwe_enrichment=cwe_enrichment,
        ),
    )


def test_rejects_missing_processor() -> None:
    with pytest.raises(
        ValueError,
        match="processor must not be None",
    ):
        CisaKevCanonicalCorrelationJob(
            processor=cast(
                CisaKevCanonicalBatchProcessor,
                None,
            ),
        )


@pytest.mark.parametrize(
    "value, error_type",
    [
        (True, TypeError),
        ("500", TypeError),
        (0, ValueError),
        (1_001, ValueError),
    ],
)
def test_rejects_invalid_batch_size(
    value: object,
    error_type: type[Exception],
) -> None:
    processor = (
        FakeCisaKevCanonicalBatchProcessor(
            results=deque()
        )
    )

    with pytest.raises(
        error_type
    ):
        CisaKevCanonicalCorrelationJob(
            processor=processor,
            batch_size=cast(
                int,
                value,
            ),
        )


@pytest.mark.parametrize(
    "value, error_type",
    [
        (True, TypeError),
        ("10", TypeError),
        (0, ValueError),
        (-1, ValueError),
    ],
)
def test_rejects_invalid_max_batches(
    value: object,
    error_type: type[Exception],
) -> None:
    processor = (
        FakeCisaKevCanonicalBatchProcessor(
            results=deque()
        )
    )

    with pytest.raises(
        error_type
    ):
        CisaKevCanonicalCorrelationJob(
            processor=processor,
            max_batches=cast(
                int,
                value,
            ),
        )


def test_returns_empty_exhausted_source() -> None:
    processor = (
        FakeCisaKevCanonicalBatchProcessor(
            results=deque(
                [
                    _batch_result(
                        records_read=0,
                        next_cursor=None,
                        source_exhausted=True,
                    )
                ]
            )
        )
    )

    job = CisaKevCanonicalCorrelationJob(
        processor=processor,
        batch_size=250,
    )

    result = job.run()

    assert result.batches_processed == 1
    assert result.records_read == 0
    assert result.source_exhausted is True
    assert result.max_batches_reached is False
    assert result.next_cursor is None

    assert processor.calls == [
        (
            None,
            250,
        )
    ]


def test_aggregates_several_batches() -> None:
    first_cursor = _cursor(1)
    second_cursor = _cursor(2)

    processor = (
        FakeCisaKevCanonicalBatchProcessor(
            results=deque(
                [
                    _batch_result(
                        records_read=2,
                        next_cursor=first_cursor,
                        source_exhausted=False,
                        observations_received=2,
                        components_built=2,
                        created=1,
                        updated=1,
                        canonical_persisted=2,
                        cwe_records_received=2,
                        cwe_records_with_references=2,
                        cwe_records_enriched=1,
                        cwe_records_without_catalogued_cwe=1,
                        association_candidates=3,
                        unique_associations=2,
                        cwe_persisted=2,
                    ),
                    _batch_result(
                        records_read=1,
                        next_cursor=second_cursor,
                        source_exhausted=True,
                        observations_received=1,
                        components_built=1,
                        created=0,
                        updated=1,
                        canonical_persisted=1,
                        cwe_records_received=1,
                        cwe_records_with_references=1,
                        cwe_records_enriched=1,
                        cwe_records_without_catalogued_cwe=0,
                        association_candidates=1,
                        unique_associations=1,
                        cwe_persisted=1,
                    ),
                ]
            )
        )
    )

    job = CisaKevCanonicalCorrelationJob(
        processor=processor,
        batch_size=100,
        max_batches=10,
    )

    result = job.run()

    assert result.batches_processed == 2
    assert result.records_read == 3

    assert result.source_exhausted is True
    assert result.max_batches_reached is False
    assert result.next_cursor == second_cursor

    assert result.observations_received == 3
    assert result.components_built == 3
    assert result.canonical_created == 1
    assert result.canonical_updated == 2
    assert result.canonical_persisted == 3

    assert result.cwe_records_received == 3
    assert (
        result.cwe_records_with_references
        == 3
    )
    assert result.cwe_records_enriched == 2
    assert (
        result
        .cwe_records_without_catalogued_cwe
        == 1
    )
    assert (
        result.cwe_association_candidates
        == 4
    )
    assert result.cwe_unique_associations == 3
    assert result.cwe_persisted == 3

    assert processor.calls == [
        (
            None,
            100,
        ),
        (
            first_cursor,
            100,
        ),
    ]


def test_rejects_cursor_that_does_not_progress() -> None:
    cursor = _cursor(10)

    processor = (
        FakeCisaKevCanonicalBatchProcessor(
            results=deque(
                [
                    _batch_result(
                        records_read=1,
                        next_cursor=cursor,
                        source_exhausted=False,
                    )
                ]
            )
        )
    )

    job = CisaKevCanonicalCorrelationJob(
        processor=processor
    )

    with pytest.raises(
        RuntimeError,
        match="cursor did not progress",
    ):
        job.run(
            after_cursor=cursor
        )


def test_rejects_empty_non_exhausted_batch() -> None:
    processor = (
        FakeCisaKevCanonicalBatchProcessor(
            results=deque(
                [
                    _batch_result(
                        records_read=0,
                        next_cursor=_cursor(20),
                        source_exhausted=False,
                    )
                ]
            )
        )
    )

    job = CisaKevCanonicalCorrelationJob(
        processor=processor
    )

    with pytest.raises(
        RuntimeError,
        match="empty non-exhausted batch",
    ):
        job.run()


def test_stops_when_max_batches_is_reached() -> None:
    cursor = _cursor(30)

    processor = (
        FakeCisaKevCanonicalBatchProcessor(
            results=deque(
                [
                    _batch_result(
                        records_read=1,
                        next_cursor=cursor,
                        source_exhausted=False,
                        observations_received=1,
                        components_built=1,
                        created=1,
                        canonical_persisted=1,
                    )
                ]
            )
        )
    )

    job = CisaKevCanonicalCorrelationJob(
        processor=processor,
        max_batches=1,
    )

    result = job.run()

    assert result.batches_processed == 1
    assert result.records_read == 1
    assert result.source_exhausted is False
    assert result.max_batches_reached is True
    assert result.next_cursor == cursor


def test_sanitizes_secrets_before_logging(
    caplog: pytest.LogCaptureFixture,
) -> None:
    logger = logging.getLogger(
        "test.cisa.canonical.job"
    )

    caplog.set_level(
        logging.ERROR,
        logger=logger.name,
    )

    job = CisaKevCanonicalCorrelationJob(
        processor=(
            FailingCisaKevCanonicalBatchProcessor()
        ),
        logger=logger,
    )

    with pytest.raises(
        RuntimeError
    ):
        job.run()

    logged_text = caplog.text

    assert "super-secret" not in logged_text
    assert "token-value" not in logged_text
    assert "hunter2" not in logged_text

    assert "***:***@db/test" in logged_text
    assert "authorization=***" in (
        logged_text.lower()
    )
    assert "password=***" in (
        logged_text.lower()
    )