from __future__ import annotations

import logging
from collections import deque
from dataclasses import (
    dataclass,
    field,
)
from uuid import UUID

import pytest

from application.models.phishtank_canonical_source_record import (
    PhishTankCanonicalCursor,
)
from application.models.urlhaus_canonical_source_record import (
    URLhausCanonicalCursor,
)
from application.services.canonical_web_indicator_correlation_service import (
    CanonicalWebCorrelationResult,
)
from application.services.phishtank_canonical_correlation_batch_service import (
    PhishTankCanonicalCorrelationBatchResult,
)
from application.services.urlhaus_canonical_correlation_batch_service import (
    URLhausCanonicalCorrelationBatchResult,
)
from infrastructure.adapters.inbound.web_canonical_correlation_job import (
    WebCanonicalCorrelationJob,
)


@dataclass(
    slots=True,
)
class FakePhishTankProcessor:
    results: deque[
        PhishTankCanonicalCorrelationBatchResult
    ]

    calls: list[
        tuple[
            PhishTankCanonicalCursor | None,
            int,
        ]
    ] = field(
        default_factory=list
    )

    def process_batch(
        self,
        *,
        after_cursor: (
            PhishTankCanonicalCursor
            | None
        ) = None,
        limit: int,
    ) -> (
        PhishTankCanonicalCorrelationBatchResult
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


@dataclass(
    slots=True,
)
class FakeURLhausProcessor:
    results: deque[
        URLhausCanonicalCorrelationBatchResult
    ]

    def process_batch(
        self,
        *,
        after_cursor: (
            URLhausCanonicalCursor
            | None
        ) = None,
        limit: int,
    ) -> (
        URLhausCanonicalCorrelationBatchResult
    ):
        del after_cursor
        del limit

        if not self.results:
            raise AssertionError(
                "No fake batch result remains"
            )

        return self.results.popleft()


class FailingPhishTankProcessor:
    def process_batch(
        self,
        *,
        after_cursor: (
            PhishTankCanonicalCursor
            | None
        ) = None,
        limit: int,
    ) -> (
        PhishTankCanonicalCorrelationBatchResult
    ):
        del after_cursor
        del limit

        raise RuntimeError(
            "failed URL "
            "https://admin:secret@example.invalid/"
            "payload?token=token-value "
            "password=hunter2 "
            "Authorization: Bearer bearer-value"
        )


def _phishtank_cursor(
    index: int,
) -> PhishTankCanonicalCursor:
    return PhishTankCanonicalCursor(
        phish_id=index,
        normalized_record_id=UUID(
            int=index
        ),
    )


def _urlhaus_cursor(
    index: int,
) -> URLhausCanonicalCursor:
    return URLhausCanonicalCursor(
        urlhaus_id=index,
        normalized_record_id=UUID(
            int=index
        ),
    )


def _correlation(
    *,
    observations_received: int = 0,
    components_built: int = 0,
    created: int = 0,
    updated: int = 0,
    persisted: int = 0,
) -> CanonicalWebCorrelationResult:
    return CanonicalWebCorrelationResult(
        observations_received=(
            observations_received
        ),
        components_built=(
            components_built
        ),
        created=created,
        updated=updated,
        persisted=persisted,
        aggregates=(),
    )


def _phishtank_result(
    *,
    records_read: int,
    next_cursor: (
        PhishTankCanonicalCursor
        | None
    ),
    source_exhausted: bool,
    correlation: (
        CanonicalWebCorrelationResult
        | None
    ) = None,
) -> (
    PhishTankCanonicalCorrelationBatchResult
):
    return (
        PhishTankCanonicalCorrelationBatchResult(
            records_read=records_read,
            next_cursor=next_cursor,
            source_exhausted=(
                source_exhausted
            ),
            correlation=(
                correlation
                or _correlation()
            ),
        )
    )


def _urlhaus_result(
    *,
    records_read: int,
    next_cursor: (
        URLhausCanonicalCursor
        | None
    ),
    source_exhausted: bool,
) -> (
    URLhausCanonicalCorrelationBatchResult
):
    return (
        URLhausCanonicalCorrelationBatchResult(
            records_read=records_read,
            next_cursor=next_cursor,
            source_exhausted=(
                source_exhausted
            ),
            correlation=_correlation(
                observations_received=(
                    records_read
                ),
                components_built=(
                    records_read
                ),
                persisted=records_read,
            ),
        )
    )


def test_aggregates_several_batches(
) -> None:
    first_cursor = (
        _phishtank_cursor(10)
    )

    second_cursor = (
        _phishtank_cursor(20)
    )

    processor = FakePhishTankProcessor(
        results=deque(
            (
                _phishtank_result(
                    records_read=2,
                    next_cursor=first_cursor,
                    source_exhausted=False,
                    correlation=_correlation(
                        observations_received=2,
                        components_built=1,
                        created=1,
                        updated=0,
                        persisted=1,
                    ),
                ),
                _phishtank_result(
                    records_read=1,
                    next_cursor=second_cursor,
                    source_exhausted=True,
                    correlation=_correlation(
                        observations_received=1,
                        components_built=1,
                        created=0,
                        updated=1,
                        persisted=1,
                    ),
                ),
            )
        )
    )

    job = WebCanonicalCorrelationJob[
        PhishTankCanonicalCursor
    ](
        processor=processor,
        batch_size=100,
        max_batches=10,
    )

    result = job.run()

    assert result.batches_processed == 2
    assert result.records_read == 3

    assert result.source_exhausted is True

    assert (
        result.max_batches_reached
        is False
    )

    assert (
        result.next_cursor
        == second_cursor
    )

    assert (
        result.observations_received
        == 3
    )

    assert result.components_built == 2
    assert result.canonical_created == 1
    assert result.canonical_updated == 1
    assert result.canonical_persisted == 2

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


def test_preserves_cursor_after_empty_exhausted_batch(
) -> None:
    cursor = _phishtank_cursor(
        100
    )

    processor = FakePhishTankProcessor(
        results=deque(
            (
                _phishtank_result(
                    records_read=0,
                    next_cursor=None,
                    source_exhausted=True,
                ),
            )
        )
    )

    job = WebCanonicalCorrelationJob[
        PhishTankCanonicalCursor
    ](
        processor=processor
    )

    result = job.run(
        after_cursor=cursor
    )

    assert result.records_read == 0

    assert result.source_exhausted is True

    assert result.next_cursor == cursor


def test_rejects_cursor_that_does_not_progress(
) -> None:
    cursor = _phishtank_cursor(
        200
    )

    processor = FakePhishTankProcessor(
        results=deque(
            (
                _phishtank_result(
                    records_read=1,
                    next_cursor=cursor,
                    source_exhausted=True,
                ),
            )
        )
    )

    job = WebCanonicalCorrelationJob[
        PhishTankCanonicalCursor
    ](
        processor=processor
    )

    with pytest.raises(
        RuntimeError,
        match="cursor did not progress",
    ):
        job.run(
            after_cursor=cursor
        )


def test_rejects_empty_non_exhausted_batch(
) -> None:
    processor = FakePhishTankProcessor(
        results=deque(
            (
                _phishtank_result(
                    records_read=0,
                    next_cursor=None,
                    source_exhausted=False,
                ),
            )
        )
    )

    job = WebCanonicalCorrelationJob[
        PhishTankCanonicalCursor
    ](
        processor=processor
    )

    with pytest.raises(
        RuntimeError,
        match="empty non-exhausted batch",
    ):
        job.run()


def test_stops_when_max_batches_is_reached(
) -> None:
    cursor = _phishtank_cursor(
        300
    )

    processor = FakePhishTankProcessor(
        results=deque(
            (
                _phishtank_result(
                    records_read=1,
                    next_cursor=cursor,
                    source_exhausted=False,
                    correlation=_correlation(
                        observations_received=1,
                        components_built=1,
                        created=1,
                        persisted=1,
                    ),
                ),
            )
        )
    )

    job = WebCanonicalCorrelationJob[
        PhishTankCanonicalCursor
    ](
        processor=processor,
        max_batches=1,
    )

    result = job.run()

    assert result.batches_processed == 1

    assert result.source_exhausted is False

    assert result.max_batches_reached is True

    assert result.next_cursor == cursor


def test_supports_urlhaus_cursor_type(
) -> None:
    cursor = _urlhaus_cursor(
        400
    )

    processor = FakeURLhausProcessor(
        results=deque(
            (
                _urlhaus_result(
                    records_read=1,
                    next_cursor=cursor,
                    source_exhausted=True,
                ),
            )
        )
    )

    job = WebCanonicalCorrelationJob[
        URLhausCanonicalCursor
    ](
        processor=processor
    )

    result = job.run()

    assert result.records_read == 1
    assert result.next_cursor == cursor
    assert result.canonical_persisted == 1


def test_sanitizes_urls_and_secrets_before_logging(
    caplog: pytest.LogCaptureFixture,
) -> None:
    logger = logging.getLogger(
        "test.web.canonical.job"
    )

    caplog.set_level(
        logging.ERROR,
        logger=logger.name,
    )

    job = WebCanonicalCorrelationJob[
        PhishTankCanonicalCursor
    ](
        processor=(
            FailingPhishTankProcessor()
        ),
        logger=logger,
    )

    with pytest.raises(
        RuntimeError
    ):
        job.run()

    logged_text = caplog.text

    assert "example.invalid" not in logged_text
    assert "admin" not in logged_text
    assert "secret" not in logged_text
    assert "token-value" not in logged_text
    assert "hunter2" not in logged_text
    assert "bearer-value" not in logged_text

    assert "[redacted-url]" in logged_text

    assert "password=***" in (
        logged_text.lower()
    )

    assert "authorization=***" in (
        logged_text.lower()
    )