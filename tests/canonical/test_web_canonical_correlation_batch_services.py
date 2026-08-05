from __future__ import annotations

from collections.abc import Iterable
from datetime import (
    UTC,
    datetime,
)
from uuid import uuid4

import pytest

from application.models.canonical_web_indicator_observation import (
    CanonicalWebIndicatorObservation,
)
from application.models.phishtank_canonical_source_record import (
    PhishTankCanonicalCursor,
    PhishTankCanonicalSourceRecord,
)
from application.models.urlhaus_canonical_source_record import (
    URLhausCanonicalCursor,
    URLhausCanonicalSourceRecord,
)
from application.ports.outbound.phishtank_canonical_source import (
    PhishTankCanonicalSource,
)
from application.ports.outbound.urlhaus_canonical_source import (
    URLhausCanonicalSource,
)
from application.services.canonical_web_indicator_correlation_service import (
    CanonicalWebCorrelationResult,
    CanonicalWebIndicatorCorrelationService,
)
from application.services.phishtank_canonical_correlation_batch_service import (
    PhishTankCanonicalCorrelationBatchService,
)
from application.services.phishtank_canonical_observation_builder import (
    PhishTankCanonicalObservationBuilder,
)
from application.services.urlhaus_canonical_correlation_batch_service import (
    URLhausCanonicalCorrelationBatchService,
)
from application.services.urlhaus_canonical_observation_builder import (
    URLhausCanonicalObservationBuilder,
)


NOW = datetime(
    2026,
    8,
    5,
    20,
    30,
    tzinfo=UTC,
)


class FakeCorrelationService(
    CanonicalWebIndicatorCorrelationService
):
    def __init__(
        self,
    ) -> None:
        self.received: tuple[
            CanonicalWebIndicatorObservation,
            ...,
        ] = ()

    def correlate(
        self,
        observations: Iterable[
            CanonicalWebIndicatorObservation
        ],
    ) -> CanonicalWebCorrelationResult:
        self.received = tuple(
            observations
        )

        count = len(
            self.received
        )

        return CanonicalWebCorrelationResult(
            observations_received=count,
            components_built=count,
            created=count,
            updated=0,
            persisted=count,
            aggregates=(),
        )


class FakePhishTankSource(
    PhishTankCanonicalSource
):
    def __init__(
        self,
        records: tuple[
            PhishTankCanonicalSourceRecord,
            ...,
        ],
    ) -> None:
        self.records = records

        self.after_cursor: (
            PhishTankCanonicalCursor
            | None
        ) = None

        self.limit: int | None = None

    def read_batch(
        self,
        *,
        after_cursor: (
            PhishTankCanonicalCursor
            | None
        ) = None,
        limit: int = 500,
    ) -> tuple[
        PhishTankCanonicalSourceRecord,
        ...,
    ]:
        self.after_cursor = after_cursor
        self.limit = limit

        return self.records


class FakeURLhausSource(
    URLhausCanonicalSource
):
    def __init__(
        self,
        records: tuple[
            URLhausCanonicalSourceRecord,
            ...,
        ],
    ) -> None:
        self.records = records

        self.after_cursor: (
            URLhausCanonicalCursor
            | None
        ) = None

        self.limit: int | None = None

    def read_batch(
        self,
        *,
        after_cursor: (
            URLhausCanonicalCursor
            | None
        ) = None,
        limit: int = 500,
    ) -> tuple[
        URLhausCanonicalSourceRecord,
        ...,
    ]:
        self.after_cursor = after_cursor
        self.limit = limit

        return self.records


def _phishtank_record(
    phish_id: int,
) -> PhishTankCanonicalSourceRecord:
    return PhishTankCanonicalSourceRecord(
        normalized_record_id=uuid4(),
        phish_id=phish_id,
        phishing_url=(
            f"https://pt-{phish_id}.invalid/path"
        ),
        normalized_at=NOW,
        normalizer_version="1.0.0",
        submission_time=NOW,
        verification_time=NOW,
        verified=True,
        online=True,
    )


def _urlhaus_record(
    urlhaus_id: int,
) -> URLhausCanonicalSourceRecord:
    return URLhausCanonicalSourceRecord(
        normalized_record_id=uuid4(),
        urlhaus_id=urlhaus_id,
        malicious_url=(
            f"https://uh-{urlhaus_id}.invalid/file"
        ),
        normalized_at=NOW,
        normalizer_version="1.0.0",
        date_added=NOW,
        url_status="online",
    )


def test_processes_phishtank_batch(
) -> None:
    records = (
        _phishtank_record(10),
        _phishtank_record(20),
    )

    source = FakePhishTankSource(
        records
    )

    correlation = (
        FakeCorrelationService()
    )

    result = (
        PhishTankCanonicalCorrelationBatchService(
            source=source,
            builder=(
                PhishTankCanonicalObservationBuilder()
            ),
            correlation_service=correlation,
        )
        .process_batch(
            limit=2
        )
    )

    assert result.records_read == 2
    assert result.next_cursor == (
        records[-1].cursor
    )

    assert result.source_exhausted is False
    assert result.correlation.persisted == 2

    assert source.limit == 2

    assert {
        item.observation.source
        for item in correlation.received
    } == {
        "phishtank",
    }


def test_processes_urlhaus_batch(
) -> None:
    records = (
        _urlhaus_record(100),
    )

    source = FakeURLhausSource(
        records
    )

    correlation = (
        FakeCorrelationService()
    )

    result = (
        URLhausCanonicalCorrelationBatchService(
            source=source,
            builder=(
                URLhausCanonicalObservationBuilder()
            ),
            correlation_service=correlation,
        )
        .process_batch(
            limit=2
        )
    )

    assert result.records_read == 1
    assert result.next_cursor == (
        records[-1].cursor
    )

    assert result.source_exhausted is True
    assert result.correlation.persisted == 1

    assert {
        item.observation.source
        for item in correlation.received
    } == {
        "urlhaus",
    }


def test_empty_batch_returns_no_cursor(
) -> None:
    source = FakeURLhausSource(
        ()
    )

    correlation = (
        FakeCorrelationService()
    )

    result = (
        URLhausCanonicalCorrelationBatchService(
            source=source,
            builder=(
                URLhausCanonicalObservationBuilder()
            ),
            correlation_service=correlation,
        )
        .process_batch(
            limit=500
        )
    )

    assert result.records_read == 0
    assert result.next_cursor is None
    assert result.source_exhausted is True

    assert (
        result
        .correlation
        .observations_received
        == 0
    )


def test_rejects_source_returning_too_many_records(
) -> None:
    source = FakePhishTankSource(
        (
            _phishtank_record(1),
            _phishtank_record(2),
        )
    )

    with pytest.raises(
        RuntimeError,
        match="more records",
    ):
        (
            PhishTankCanonicalCorrelationBatchService(
                source=source,
                builder=(
                    PhishTankCanonicalObservationBuilder()
                ),
                correlation_service=(
                    FakeCorrelationService()
                ),
            )
            .process_batch(
                limit=1
            )
        )


@pytest.mark.parametrize(
    "limit",
    [
        0,
        1_001,
    ],
)
def test_rejects_invalid_batch_limit(
    limit: int,
) -> None:
    with pytest.raises(
        ValueError,
        match="between 1 and 1000",
    ):
        (
            URLhausCanonicalCorrelationBatchService(
                source=FakeURLhausSource(
                    ()
                ),
                builder=(
                    URLhausCanonicalObservationBuilder()
                ),
                correlation_service=(
                    FakeCorrelationService()
                ),
            )
            .process_batch(
                limit=limit
            )
        )