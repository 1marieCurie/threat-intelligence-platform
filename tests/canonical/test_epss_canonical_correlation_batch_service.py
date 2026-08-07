from __future__ import annotations

from datetime import (
    UTC,
    date,
    datetime,
)
from typing import cast
from unittest.mock import Mock

import pytest

from application.models.epss_canonical_source_record import (
    EPSSCanonicalSourceRecord,
)
from application.models.epss_snapshot import (
    EPSSSnapshot,
)
from application.ports.outbound.epss_canonical_source import (
    EPSSCanonicalSource,
)
from application.services.canonical_epss_enrichment_service import (
    CanonicalEPSSEnrichmentService,
)
from application.services.canonical_vulnerability_correlation_service import (
    CanonicalCorrelationResult,
    CanonicalVulnerabilityCorrelationService,
)
from application.services.epss_canonical_correlation_batch_service import (
    EPSSCanonicalCorrelationBatchService,
)
from application.services.epss_canonical_observation_builder import (
    EPSSCanonicalObservationBuilder,
)


def _record(
    *,
    cve_id: str,
    day: int,
) -> EPSSCanonicalSourceRecord:
    return EPSSCanonicalSourceRecord(
        cve_id=cve_id,
        snapshot=EPSSSnapshot(
            score=0.42,
            percentile=0.87,
            score_date=date(
                2026,
                8,
                day,
            ),
            api_version="v1",
        ),
        synchronized_at=datetime(
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


def _build_source_mock(
) -> tuple[
    Mock,
    EPSSCanonicalSource,
]:
    mock = Mock(
        spec=EPSSCanonicalSource,
    )

    return (
        mock,
        cast(
            EPSSCanonicalSource,
            mock,
        ),
    )


def _build_correlation_mock(
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


def _build_enrichment_mock(
) -> tuple[
    Mock,
    CanonicalEPSSEnrichmentService,
]:
    mock = Mock(
        spec=(
            CanonicalEPSSEnrichmentService
        ),
    )

    return (
        mock,
        cast(
            CanonicalEPSSEnrichmentService,
            mock,
        ),
    )


def test_constructor_rejects_missing_source(
) -> None:
    _, correlation = (
        _build_correlation_mock()
    )

    _, enrichment = (
        _build_enrichment_mock()
    )

    with pytest.raises(
        ValueError,
        match="source must not be None",
    ):
        EPSSCanonicalCorrelationBatchService(
            source=None,  # type: ignore[arg-type]
            builder=(
                EPSSCanonicalObservationBuilder()
            ),
            correlation_service=correlation,
            epss_enrichment_service=enrichment,
        )


def test_constructor_rejects_missing_builder(
) -> None:
    _, source = _build_source_mock()

    _, correlation = (
        _build_correlation_mock()
    )

    _, enrichment = (
        _build_enrichment_mock()
    )

    with pytest.raises(
        ValueError,
        match="builder must not be None",
    ):
        EPSSCanonicalCorrelationBatchService(
            source=source,
            builder=None,  # type: ignore[arg-type]
            correlation_service=correlation,
            epss_enrichment_service=enrichment,
        )


def test_constructor_rejects_missing_correlation_service(
) -> None:
    _, source = _build_source_mock()

    _, enrichment = (
        _build_enrichment_mock()
    )

    with pytest.raises(
        ValueError,
        match=(
            "correlation_service "
            "must not be None"
        ),
    ):
        EPSSCanonicalCorrelationBatchService(
            source=source,
            builder=(
                EPSSCanonicalObservationBuilder()
            ),
            correlation_service=None,  # type: ignore[arg-type]
            epss_enrichment_service=enrichment,
        )


def test_constructor_rejects_missing_enrichment_service(
) -> None:
    _, source = _build_source_mock()

    _, correlation = (
        _build_correlation_mock()
    )

    with pytest.raises(
        ValueError,
        match=(
            "epss_enrichment_service "
            "must not be None"
        ),
    ):
        EPSSCanonicalCorrelationBatchService(
            source=source,
            builder=(
                EPSSCanonicalObservationBuilder()
            ),
            correlation_service=correlation,
            epss_enrichment_service=None,  # type: ignore[arg-type]
        )


def test_process_batch_builds_correlates_and_enriches_once(
) -> None:
    source_mock, source = (
        _build_source_mock()
    )

    correlation_mock, correlation = (
        _build_correlation_mock()
    )

    enrichment_mock, enrichment = (
        _build_enrichment_mock()
    )

    records = (
        _record(
            cve_id="CVE-2026-10001",
            day=3,
        ),
        _record(
            cve_id="CVE-2026-10002",
            day=4,
        ),
    )

    source_mock.read_batch.return_value = (
        records
    )

    expected_correlation = (
        _correlation_result(
            observations=2,
            created=2,
        )
    )

    correlation_mock.correlate.return_value = (
        expected_correlation
    )

    expected_enrichment = Mock(
        name="epss_enrichment_result",
    )

    enrichment_mock.enrich.return_value = (
        expected_enrichment
    )

    service = (
        EPSSCanonicalCorrelationBatchService(
            source=source,
            builder=(
                EPSSCanonicalObservationBuilder()
            ),
            correlation_service=correlation,
            epss_enrichment_service=enrichment,
        )
    )

    result = service.process_batch(
        after_cve_id="CVE-2026-10000",
        limit=2,
    )

    source_mock.read_batch \
        .assert_called_once_with(
            after_cve_id=(
                "CVE-2026-10000"
            ),
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

    assert [
        observation
        .identifiers[0]
        .value
        for observation in observations
    ] == [
        "CVE-2026-10001",
        "CVE-2026-10002",
    ]

    assert [
        observation.evidence.key
        for observation in observations
    ] == [
        (
            "epss",
            "CVE-2026-10001",
        ),
        (
            "epss",
            "CVE-2026-10002",
        ),
    ]

    enrichment_mock.enrich \
        .assert_called_once_with(
            records=records,
            aggregates=(
                expected_correlation.aggregates
            ),
        )

    assert result.records_read == 2

    assert (
        result.next_cursor
        == "CVE-2026-10002"
    )

    assert result.source_exhausted is False

    assert (
        result.correlation
        is expected_correlation
    )

    assert (
        result.epss_enrichment
        is expected_enrichment
    )


def test_process_batch_handles_empty_source(
) -> None:
    source_mock, source = (
        _build_source_mock()
    )

    correlation_mock, correlation = (
        _build_correlation_mock()
    )

    enrichment_mock, enrichment = (
        _build_enrichment_mock()
    )

    source_mock.read_batch.return_value = ()

    empty_correlation = (
        _correlation_result(
            observations=0
        )
    )

    correlation_mock.correlate.return_value = (
        empty_correlation
    )

    empty_enrichment = Mock(
        name="empty_epss_enrichment_result",
    )

    enrichment_mock.enrich.return_value = (
        empty_enrichment
    )

    result = (
        EPSSCanonicalCorrelationBatchService(
            source=source,
            builder=(
                EPSSCanonicalObservationBuilder()
            ),
            correlation_service=correlation,
            epss_enrichment_service=enrichment,
        )
        .process_batch(
            after_cve_id=(
                "CVE-2026-99999"
            ),
            limit=50,
        )
    )

    correlation_mock.correlate \
        .assert_called_once_with(
            ()
        )

    enrichment_mock.enrich \
        .assert_called_once_with(
            records=(),
            aggregates=(),
        )

    assert result.records_read == 0
    assert result.next_cursor is None
    assert result.source_exhausted is True

    assert (
        result.correlation
        is empty_correlation
    )

    assert (
        result.epss_enrichment
        is empty_enrichment
    )


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
    source_mock, source = (
        _build_source_mock()
    )

    correlation_mock, correlation = (
        _build_correlation_mock()
    )

    enrichment_mock, enrichment = (
        _build_enrichment_mock()
    )

    service = (
        EPSSCanonicalCorrelationBatchService(
            source=source,
            builder=(
                EPSSCanonicalObservationBuilder()
            ),
            correlation_service=correlation,
            epss_enrichment_service=enrichment,
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
    enrichment_mock.enrich.assert_not_called()


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
    source_mock, source = (
        _build_source_mock()
    )

    correlation_mock, correlation = (
        _build_correlation_mock()
    )

    enrichment_mock, enrichment = (
        _build_enrichment_mock()
    )

    service = (
        EPSSCanonicalCorrelationBatchService(
            source=source,
            builder=(
                EPSSCanonicalObservationBuilder()
            ),
            correlation_service=correlation,
            epss_enrichment_service=enrichment,
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
    enrichment_mock.enrich.assert_not_called()


def test_process_batch_rejects_source_overflow(
) -> None:
    source_mock, source = (
        _build_source_mock()
    )

    correlation_mock, correlation = (
        _build_correlation_mock()
    )

    enrichment_mock, enrichment = (
        _build_enrichment_mock()
    )

    source_mock.read_batch.return_value = (
        _record(
            cve_id="CVE-2026-20001",
            day=3,
        ),
        _record(
            cve_id="CVE-2026-20002",
            day=4,
        ),
    )

    service = (
        EPSSCanonicalCorrelationBatchService(
            source=source,
            builder=(
                EPSSCanonicalObservationBuilder()
            ),
            correlation_service=correlation,
            epss_enrichment_service=enrichment,
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
    enrichment_mock.enrich.assert_not_called()


def test_process_batch_does_not_enrich_after_builder_failure(
) -> None:
    source_mock, source = (
        _build_source_mock()
    )

    correlation_mock, correlation = (
        _build_correlation_mock()
    )

    enrichment_mock, enrichment = (
        _build_enrichment_mock()
    )

    builder_mock = Mock(
        spec=(
            EPSSCanonicalObservationBuilder
        ),
    )

    builder = cast(
        EPSSCanonicalObservationBuilder,
        builder_mock,
    )

    source_mock.read_batch.return_value = (
        _record(
            cve_id="CVE-2026-30001",
            day=4,
        ),
    )

    builder_mock.build.side_effect = (
        RuntimeError(
            "builder failure"
        )
    )

    service = (
        EPSSCanonicalCorrelationBatchService(
            source=source,
            builder=builder,
            correlation_service=correlation,
            epss_enrichment_service=enrichment,
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
    enrichment_mock.enrich.assert_not_called()


def test_process_batch_does_not_enrich_after_correlation_failure(
) -> None:
    source_mock, source = (
        _build_source_mock()
    )

    correlation_mock, correlation = (
        _build_correlation_mock()
    )

    enrichment_mock, enrichment = (
        _build_enrichment_mock()
    )

    source_mock.read_batch.return_value = (
        _record(
            cve_id="CVE-2026-40001",
            day=4,
        ),
    )

    correlation_mock.correlate.side_effect = (
        RuntimeError(
            "correlation failure"
        )
    )

    service = (
        EPSSCanonicalCorrelationBatchService(
            source=source,
            builder=(
                EPSSCanonicalObservationBuilder()
            ),
            correlation_service=correlation,
            epss_enrichment_service=enrichment,
        )
    )

    with pytest.raises(
        RuntimeError,
        match="correlation failure",
    ):
        service.process_batch(
            limit=10
        )

    source_mock.read_batch \
        .assert_called_once()

    correlation_mock.correlate \
        .assert_called_once()

    enrichment_mock.enrich.assert_not_called()


def test_process_batch_propagates_enrichment_failure(
) -> None:
    source_mock, source = (
        _build_source_mock()
    )

    correlation_mock, correlation = (
        _build_correlation_mock()
    )

    enrichment_mock, enrichment = (
        _build_enrichment_mock()
    )

    records = (
        _record(
            cve_id="CVE-2026-50001",
            day=4,
        ),
    )

    source_mock.read_batch.return_value = (
        records
    )

    correlation_result = (
        _correlation_result(
            observations=1,
            created=1,
        )
    )

    correlation_mock.correlate.return_value = (
        correlation_result
    )

    enrichment_mock.enrich.side_effect = (
        RuntimeError(
            "enrichment failure"
        )
    )

    service = (
        EPSSCanonicalCorrelationBatchService(
            source=source,
            builder=(
                EPSSCanonicalObservationBuilder()
            ),
            correlation_service=correlation,
            epss_enrichment_service=enrichment,
        )
    )

    with pytest.raises(
        RuntimeError,
        match="enrichment failure",
    ):
        service.process_batch(
            limit=10
        )

    correlation_mock.correlate \
        .assert_called_once()

    enrichment_mock.enrich \
        .assert_called_once_with(
            records=records,
            aggregates=(
                correlation_result.aggregates
            ),
        )