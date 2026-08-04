from __future__ import annotations

from datetime import (
    UTC,
    datetime,
)
from typing import cast
from unittest.mock import Mock
from uuid import UUID

import pytest

from application.models.github_advisory_canonical_source_record import (
    GitHubAdvisoryCanonicalCursor,
    GitHubAdvisoryCanonicalSourceRecord,
)
from application.ports.outbound.github_advisory_canonical_source import (
    GitHubAdvisoryCanonicalSource,
)
from application.services.canonical_vulnerability_correlation_service import (
    CanonicalCorrelationResult,
    CanonicalVulnerabilityCorrelationService,
)
from application.services.github_advisory_canonical_correlation_batch_service import (
    GitHubAdvisoryCanonicalCorrelationBatchService,
)
from application.services.github_advisory_canonical_observation_builder import (
    GitHubAdvisoryCanonicalObservationBuilder,
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
    source_ghsa_id: str,
    day: int,
    cve_id: str | None = None,
) -> GitHubAdvisoryCanonicalSourceRecord:
    return GitHubAdvisoryCanonicalSourceRecord(
        normalized_record_id=(
            normalized_record_id
        ),
        ghsa_id=source_ghsa_id,
        source_ghsa_id=source_ghsa_id,
        cve_id=cve_id,
        published_at=datetime(
            2026,
            8,
            1,
            10,
            0,
            tzinfo=UTC,
        ),
        updated_at=datetime(
            2026,
            8,
            day,
            11,
            0,
            tzinfo=UTC,
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
    components: int | None = None,
    created: int = 0,
    updated: int = 0,
) -> CanonicalCorrelationResult:
    component_count = (
        observations
        if components is None
        else components
    )

    return CanonicalCorrelationResult(
        observations_received=observations,
        components_built=component_count,
        created=created,
        updated=updated,
        persisted=created + updated,
        aggregates=(),
    )


def _source_mock(
) -> tuple[
    Mock,
    GitHubAdvisoryCanonicalSource,
]:
    mock = Mock(
        spec=GitHubAdvisoryCanonicalSource,
    )

    return (
        mock,
        cast(
            GitHubAdvisoryCanonicalSource,
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


def _service(
    *,
    source: GitHubAdvisoryCanonicalSource,
    correlation: (
        CanonicalVulnerabilityCorrelationService
    ),
) -> GitHubAdvisoryCanonicalCorrelationBatchService:
    return (
        GitHubAdvisoryCanonicalCorrelationBatchService(
            source=source,
            builder=(
                GitHubAdvisoryCanonicalObservationBuilder()
            ),
            correlation_service=correlation,
        )
    )


def test_constructor_rejects_missing_source(
) -> None:
    _, correlation = _correlation_mock()

    with pytest.raises(
        ValueError,
        match="source must not be None",
    ):
        GitHubAdvisoryCanonicalCorrelationBatchService(
            source=None,  # type: ignore[arg-type]
            builder=(
                GitHubAdvisoryCanonicalObservationBuilder()
            ),
            correlation_service=correlation,
        )


def test_constructor_rejects_missing_builder(
) -> None:
    _, source = _source_mock()
    _, correlation = _correlation_mock()

    with pytest.raises(
        ValueError,
        match="builder must not be None",
    ):
        GitHubAdvisoryCanonicalCorrelationBatchService(
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
        GitHubAdvisoryCanonicalCorrelationBatchService(
            source=source,
            builder=(
                GitHubAdvisoryCanonicalObservationBuilder()
            ),
            correlation_service=None,  # type: ignore[arg-type]
        )


def test_process_batch_builds_and_correlates_observations(
) -> None:
    source_mock, source = _source_mock()

    correlation_mock, correlation = (
        _correlation_mock()
    )

    source_mock.read_batch.return_value = (
        _record(
            normalized_record_id=_FIRST_ID,
            source_ghsa_id=(
                "GHSA-abcd-1234-efgh"
            ),
            day=2,
        ),
        _record(
            normalized_record_id=_SECOND_ID,
            source_ghsa_id=(
                "GHSA-abcd-1234-efgh"
            ),
            cve_id="CVE-2026-12345",
            day=3,
        ),
    )

    expected = _correlation_result(
        observations=2,
        components=1,
        created=1,
    )

    correlation_mock.correlate.return_value = (
        expected
    )

    initial_cursor = (
        GitHubAdvisoryCanonicalCursor(
            ghsa_id="GHSA-0000-0000-0000",
            normalized_record_id=_FIRST_ID,
        )
    )

    result = _service(
        source=source,
        correlation=correlation,
    ).process_batch(
        after_cursor=initial_cursor,
        limit=2,
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

    first = observations[0]
    second = observations[1]

    assert [
        identifier.key
        for identifier
        in first.identifiers
    ] == [
        (
            "GHSA",
            "GHSA-ABCD-1234-EFGH",
        )
    ]

    assert {
        identifier.key
        for identifier
        in second.identifiers
    } == {
        (
            "GHSA",
            "GHSA-ABCD-1234-EFGH",
        ),
        (
            "CVE",
            "CVE-2026-12345",
        ),
    }

    assert all(
        observation.suggested_status
        == "provisional"
        for observation in observations
    )

    assert result.records_read == 2

    assert result.next_cursor == (
        GitHubAdvisoryCanonicalCursor(
            ghsa_id="GHSA-abcd-1234-efgh",
            normalized_record_id=_SECOND_ID,
        )
    )

    assert result.source_exhausted is False
    assert result.correlation is expected


def test_process_batch_handles_empty_source(
) -> None:
    source_mock, source = _source_mock()

    correlation_mock, correlation = (
        _correlation_mock()
    )

    source_mock.read_batch.return_value = ()

    expected = _correlation_result(
        observations=0,
    )

    correlation_mock.correlate.return_value = (
        expected
    )

    result = _service(
        source=source,
        correlation=correlation,
    ).process_batch(
        limit=50
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

    service = _service(
        source=source,
        correlation=correlation,
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

    service = _service(
        source=source,
        correlation=correlation,
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
            source_ghsa_id=(
                "GHSA-abcd-1234-efgh"
            ),
            day=2,
        ),
        _record(
            normalized_record_id=_SECOND_ID,
            source_ghsa_id=(
                "GHSA-1111-2222-3333"
            ),
            day=3,
        ),
    )

    with pytest.raises(
        RuntimeError,
        match=(
            "source returned more records "
            "than requested"
        ),
    ):
        _service(
            source=source,
            correlation=correlation,
        ).process_batch(
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
            GitHubAdvisoryCanonicalObservationBuilder
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
            source_ghsa_id=(
                "GHSA-abcd-1234-efgh"
            ),
            day=2,
        ),
    )

    service = (
        GitHubAdvisoryCanonicalCorrelationBatchService(
            source=source,
            builder=cast(
                GitHubAdvisoryCanonicalObservationBuilder,
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
            source_ghsa_id=(
                "GHSA-abcd-1234-efgh"
            ),
            day=2,
        ),
    )

    correlation_mock.correlate.side_effect = (
        RuntimeError(
            "correlation failure"
        )
    )

    with pytest.raises(
        RuntimeError,
        match="correlation failure",
    ):
        _service(
            source=source,
            correlation=correlation,
        ).process_batch(
            limit=10
        )

    correlation_mock.correlate \
        .assert_called_once()