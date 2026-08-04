from __future__ import annotations

from datetime import (
    UTC,
    date,
    datetime,
)
from typing import cast
from unittest.mock import Mock
from uuid import UUID

import pytest

from application.models.cisa_kev_canonical_source_record import (
    CisaKevCanonicalCursor,
    CisaKevCanonicalSourceRecord,
)
from application.ports.outbound.cisa_kev_canonical_source import (
    CisaKevCanonicalSource,
)
from application.services.canonical_vulnerability_correlation_service import (
    CanonicalCorrelationResult,
    CanonicalVulnerabilityCorrelationService,
)
from application.services.cisa_kev_canonical_correlation_batch_service import (
    CisaKevCanonicalCorrelationBatchService,
)
from application.services.cisa_kev_canonical_observation_builder import (
    CisaKevCanonicalObservationBuilder,
)


_FIRST_ID = UUID(
    "00000000-0000-0000-0000-000000000001"
)

_SECOND_ID = UUID(
    "00000000-0000-0000-0000-000000000002"
)


def _record(
    *,
    normalized_record_id: UUID,
    cve_id: str,
    day: int,
) -> CisaKevCanonicalSourceRecord:
    return CisaKevCanonicalSourceRecord(
        normalized_record_id=(
            normalized_record_id
        ),
        cve_id=cve_id,
        date_added=date(
            2026,
            8,
            day,
        ),
        normalized_at=datetime(
            2026,
            8,
            day,
            12,
            0,
            tzinfo=UTC,
        ),
    )


def _correlation_result(
    *,
    observations: int,
    created: int = 0,
    updated: int = 0,
) -> CanonicalCorrelationResult:
    return CanonicalCorrelationResult(
        observations_received=observations,
        components_built=observations,
        created=created,
        updated=updated,
        persisted=created + updated,
        aggregates=(),
    )


def _source_mock(
) -> tuple[
    Mock,
    CisaKevCanonicalSource,
]:
    mock = Mock(
        spec=CisaKevCanonicalSource,
    )

    return (
        mock,
        cast(
            CisaKevCanonicalSource,
            mock,
        ),
    )


def _correlation_mock(
) -> tuple[
    Mock,
    CanonicalVulnerabilityCorrelationService,
]:
    mock = Mock(
        spec=(
            CanonicalVulnerabilityCorrelationService
        ),
    )

    return (
        mock,
        cast(
            CanonicalVulnerabilityCorrelationService,
            mock,
        ),
    )


def test_constructor_rejects_missing_source(
) -> None:
    _, correlation = (
        _correlation_mock()
    )

    with pytest.raises(
        ValueError,
        match="source must not be None",
    ):
        CisaKevCanonicalCorrelationBatchService(
            source=None,  # type: ignore[arg-type]
            builder=(
                CisaKevCanonicalObservationBuilder()
            ),
            correlation_service=correlation,
        )


def test_constructor_rejects_missing_builder(
) -> None:
    _, source = _source_mock()
    _, correlation = (
        _correlation_mock()
    )

    with pytest.raises(
        ValueError,
        match="builder must not be None",
    ):
        CisaKevCanonicalCorrelationBatchService(
            source=source,
            builder=None,  # type: ignore[arg-type]
            correlation_service=correlation,
        )


def test_constructor_rejects_missing_correlation_service(
) -> None:
    _, source = _source_mock()

    with pytest.raises(
        ValueError,
        match=(
            "correlation_service "
            "must not be None"
        ),
    ):
        CisaKevCanonicalCorrelationBatchService(
            source=source,
            builder=(
                CisaKevCanonicalObservationBuilder()
            ),
            correlation_service=None,  # type: ignore[arg-type]
        )


def test_process_batch_builds_active_observations(
) -> None:
    source_mock, source = _source_mock()

    correlation_mock, correlation = (
        _correlation_mock()
    )

    source_mock.read_batch.return_value = (
        _record(
            normalized_record_id=_FIRST_ID,
            cve_id="CVE-2026-10001",
            day=3,
        ),
        _record(
            normalized_record_id=_SECOND_ID,
            cve_id="CVE-2026-10002",
            day=4,
        ),
    )

    expected = _correlation_result(
        observations=2,
        created=2,
    )

    correlation_mock.correlate.return_value = (
        expected
    )

    initial_cursor = CisaKevCanonicalCursor(
        cve_id="CVE-2026-10000",
        normalized_record_id=_FIRST_ID,
    )

    result = (
        CisaKevCanonicalCorrelationBatchService(
            source=source,
            builder=(
                CisaKevCanonicalObservationBuilder()
            ),
            correlation_service=correlation,
        )
        .process_batch(
            after_cursor=initial_cursor,
            limit=2,
        )
    )

    source_mock.read_batch \
        .assert_called_once_with(
            after_cursor=initial_cursor,
            limit=2,
        )

    correlation_mock.correlate \
        .assert_called_once()

    observations = (
        correlation_mock
        .correlate
        .call_args
        .args[0]
    )

    assert len(observations) == 2

    assert all(
        observation.suggested_status
        == "active"
        for observation in observations
    )

    assert [
        observation.identifiers[0].value
        for observation in observations
    ] == [
        "CVE-2026-10001",
        "CVE-2026-10002",
    ]

    assert result.records_read == 2

    assert result.next_cursor == (
        CisaKevCanonicalCursor(
            cve_id="CVE-2026-10002",
            normalized_record_id=(
                _SECOND_ID
            ),
        )
    )

    assert result.source_exhausted is False
    assert result.correlation is expected


def test_process_batch_preserves_duplicate_cve_records(
) -> None:
    source_mock, source = _source_mock()

    correlation_mock, correlation = (
        _correlation_mock()
    )

    source_mock.read_batch.return_value = (
        _record(
            normalized_record_id=_FIRST_ID,
            cve_id="CVE-2026-20001",
            day=3,
        ),
        _record(
            normalized_record_id=_SECOND_ID,
            cve_id="CVE-2026-20001",
            day=4,
        ),
    )

    correlation_mock.correlate.return_value = (
        _correlation_result(
            observations=2,
            updated=1,
        )
    )

    CisaKevCanonicalCorrelationBatchService(
        source=source,
        builder=(
            CisaKevCanonicalObservationBuilder()
        ),
        correlation_service=correlation,
    ).process_batch(
        limit=2
    )

    observations = (
        correlation_mock
        .correlate
        .call_args
        .args[0]
    )

    assert len(observations) == 2

    assert {
        observation.identifiers[0].value
        for observation in observations
    } == {
        "CVE-2026-20001",
    }

    assert {
        observation.evidence.key
        for observation in observations
    } == {
        (
            "cisa_kev",
            "CVE-2026-20001",
        ),
    }

    assert {
        observation
        .evidence
        .normalized_record_id
        for observation in observations
    } == {
        str(_FIRST_ID),
        str(_SECOND_ID),
    }


def test_process_batch_handles_empty_source(
) -> None:
    source_mock, source = _source_mock()

    correlation_mock, correlation = (
        _correlation_mock()
    )

    source_mock.read_batch.return_value = ()

    expected = _correlation_result(
        observations=0
    )

    correlation_mock.correlate.return_value = (
        expected
    )

    result = (
        CisaKevCanonicalCorrelationBatchService(
            source=source,
            builder=(
                CisaKevCanonicalObservationBuilder()
            ),
            correlation_service=correlation,
        )
        .process_batch(
            limit=50
        )
    )

    correlation_mock.correlate \
        .assert_called_once_with(
            ()
        )

    assert result.records_read == 0
    assert result.next_cursor is None
    assert result.source_exhausted is True
    assert result.correlation is expected


@pytest.mark.parametrize(
    "invalid_limit",
    [
        True,
        1.5,
        "100",
    ],
)
def test_process_batch_rejects_non_integer_limit(
    invalid_limit: object,
) -> None:
    source_mock, source = _source_mock()

    correlation_mock, correlation = (
        _correlation_mock()
    )

    service = (
        CisaKevCanonicalCorrelationBatchService(
            source=source,
            builder=(
                CisaKevCanonicalObservationBuilder()
            ),
            correlation_service=correlation,
        )
    )

    with pytest.raises(
        TypeError,
        match="limit must be an integer",
    ):
        service.process_batch(
            limit=invalid_limit,  # type: ignore[arg-type]
        )

    source_mock.read_batch.assert_not_called()
    correlation_mock.correlate.assert_not_called()


@pytest.mark.parametrize(
    "invalid_limit",
    [
        0,
        -1,
        1_001,
    ],
)
def test_process_batch_rejects_out_of_range_limit(
    invalid_limit: int,
) -> None:
    source_mock, source = _source_mock()

    correlation_mock, correlation = (
        _correlation_mock()
    )

    service = (
        CisaKevCanonicalCorrelationBatchService(
            source=source,
            builder=(
                CisaKevCanonicalObservationBuilder()
            ),
            correlation_service=correlation,
        )
    )

    with pytest.raises(
        ValueError,
        match=(
            "limit must be between "
            "1 and 1000"
        ),
    ):
        service.process_batch(
            limit=invalid_limit
        )

    source_mock.read_batch.assert_not_called()
    correlation_mock.correlate.assert_not_called()


def test_process_batch_rejects_source_overflow(
) -> None:
    source_mock, source = _source_mock()

    correlation_mock, correlation = (
        _correlation_mock()
    )

    source_mock.read_batch.return_value = (
        _record(
            normalized_record_id=_FIRST_ID,
            cve_id="CVE-2026-30001",
            day=3,
        ),
        _record(
            normalized_record_id=_SECOND_ID,
            cve_id="CVE-2026-30002",
            day=4,
        ),
    )

    service = (
        CisaKevCanonicalCorrelationBatchService(
            source=source,
            builder=(
                CisaKevCanonicalObservationBuilder()
            ),
            correlation_service=correlation,
        )
    )

    with pytest.raises(
        RuntimeError,
        match=(
            "source returned more records "
            "than requested"
        ),
    ):
        service.process_batch(
            limit=1
        )

    correlation_mock.correlate.assert_not_called()


def test_process_batch_propagates_builder_failure(
) -> None:
    source_mock, source = _source_mock()

    correlation_mock, correlation = (
        _correlation_mock()
    )

    builder_mock = Mock(
        spec=(
            CisaKevCanonicalObservationBuilder
        ),
    )

    builder_mock.build.side_effect = (
        RuntimeError(
            "builder failure"
        )
    )

    source_mock.read_batch.return_value = (
        _record(
            normalized_record_id=_FIRST_ID,
            cve_id="CVE-2026-40001",
            day=4,
        ),
    )

    service = (
        CisaKevCanonicalCorrelationBatchService(
            source=source,
            builder=cast(
                CisaKevCanonicalObservationBuilder,
                builder_mock,
            ),
            correlation_service=correlation,
        )
    )

    with pytest.raises(
        RuntimeError,
        match="builder failure",
    ):
        service.process_batch(
            limit=10
        )

    correlation_mock.correlate.assert_not_called()


def test_process_batch_propagates_correlation_failure(
) -> None:
    source_mock, source = _source_mock()

    correlation_mock, correlation = (
        _correlation_mock()
    )

    source_mock.read_batch.return_value = (
        _record(
            normalized_record_id=_FIRST_ID,
            cve_id="CVE-2026-50001",
            day=4,
        ),
    )

    correlation_mock.correlate.side_effect = (
        RuntimeError(
            "correlation failure"
        )
    )

    service = (
        CisaKevCanonicalCorrelationBatchService(
            source=source,
            builder=(
                CisaKevCanonicalObservationBuilder()
            ),
            correlation_service=correlation,
        )
    )

    with pytest.raises(
        RuntimeError,
        match="correlation failure",
    ):
        service.process_batch(
            limit=10
        )

    correlation_mock.correlate \
        .assert_called_once()