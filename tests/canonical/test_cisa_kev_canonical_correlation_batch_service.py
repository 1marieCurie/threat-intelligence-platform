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
from application.services.canonical_cwe_enrichment_service import (
    CanonicalCWEEnrichmentResult,
    CanonicalCWEEnrichmentService,
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
    cwe_ids: tuple[str, ...] = (
        "CWE-79",
    ),
) -> CisaKevCanonicalSourceRecord:
    return CisaKevCanonicalSourceRecord(
        normalized_record_id=(
            normalized_record_id
        ),
        cve_id=cve_id,
        cwe_ids=cwe_ids,
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


def _enrichment_result(
    *,
    records: int,
    persisted: int = 0,
) -> CanonicalCWEEnrichmentResult:
    return CanonicalCWEEnrichmentResult(
        records_received=records,
        records_with_cwe_references=records,
        records_enriched=records,
        records_without_catalogued_cwe=0,
        requested_unique_cwe_ids=(
            1 if records else 0
        ),
        found_unique_cwe_ids=(
            1 if records else 0
        ),
        missing_cwe_ids=(),
        association_candidates=persisted,
        unique_associations=persisted,
        persisted=persisted,
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


def _enrichment_mock(
) -> tuple[
    Mock,
    CanonicalCWEEnrichmentService,
]:
    mock = Mock(
        spec=CanonicalCWEEnrichmentService,
    )

    return (
        mock,
        cast(
            CanonicalCWEEnrichmentService,
            mock,
        ),
    )


def _service(
    *,
    source: CisaKevCanonicalSource,
    correlation: (
        CanonicalVulnerabilityCorrelationService
    ),
    enrichment: CanonicalCWEEnrichmentService,
) -> CisaKevCanonicalCorrelationBatchService:
    return CisaKevCanonicalCorrelationBatchService(
        source=source,
        builder=(
            CisaKevCanonicalObservationBuilder()
        ),
        correlation_service=correlation,
        cwe_enrichment_service=enrichment,
    )


def test_constructor_rejects_missing_source(
) -> None:
    _, correlation = _correlation_mock()
    _, enrichment = _enrichment_mock()

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
            cwe_enrichment_service=enrichment,
        )


def test_constructor_rejects_missing_builder(
) -> None:
    _, source = _source_mock()
    _, correlation = _correlation_mock()
    _, enrichment = _enrichment_mock()

    with pytest.raises(
        ValueError,
        match="builder must not be None",
    ):
        CisaKevCanonicalCorrelationBatchService(
            source=source,
            builder=None,  # type: ignore[arg-type]
            correlation_service=correlation,
            cwe_enrichment_service=enrichment,
        )


def test_constructor_rejects_missing_correlation_service(
) -> None:
    _, source = _source_mock()
    _, enrichment = _enrichment_mock()

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
            cwe_enrichment_service=enrichment,
        )


def test_constructor_rejects_missing_enrichment_service(
) -> None:
    _, source = _source_mock()
    _, correlation = _correlation_mock()

    with pytest.raises(
        ValueError,
        match=(
            "cwe_enrichment_service "
            "must not be None"
        ),
    ):
        CisaKevCanonicalCorrelationBatchService(
            source=source,
            builder=(
                CisaKevCanonicalObservationBuilder()
            ),
            correlation_service=correlation,
            cwe_enrichment_service=None,  # type: ignore[arg-type]
        )


def test_process_batch_correlates_and_enriches_records(
) -> None:
    source_mock, source = _source_mock()

    correlation_mock, correlation = (
        _correlation_mock()
    )

    enrichment_mock, enrichment = (
        _enrichment_mock()
    )

    records = (
        _record(
            normalized_record_id=_FIRST_ID,
            cve_id="CVE-2026-10001",
            day=3,
        ),
        _record(
            normalized_record_id=_SECOND_ID,
            cve_id="CVE-2026-10002",
            cwe_ids=(
                "CWE-79",
                "CWE-89",
            ),
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

    expected_enrichment = (
        _enrichment_result(
            records=2,
            persisted=3,
        )
    )

    correlation_mock.correlate.return_value = (
        expected_correlation
    )

    enrichment_mock.enrich.return_value = (
        expected_enrichment
    )

    initial_cursor = CisaKevCanonicalCursor(
        cve_id="CVE-2026-10000",
        normalized_record_id=_FIRST_ID,
    )

    result = _service(
        source=source,
        correlation=correlation,
        enrichment=enrichment,
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

    enrichment_mock.enrich \
        .assert_called_once_with(
            records=records,
            aggregates=(
                expected_correlation.aggregates
            ),
        )

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

    assert (
        result.correlation
        is expected_correlation
    )

    assert (
        result.cwe_enrichment
        is expected_enrichment
    )


def test_process_batch_preserves_duplicate_cve_records(
) -> None:
    source_mock, source = _source_mock()

    correlation_mock, correlation = (
        _correlation_mock()
    )

    enrichment_mock, enrichment = (
        _enrichment_mock()
    )

    records = (
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

    source_mock.read_batch.return_value = (
        records
    )

    expected_correlation = (
        _correlation_result(
            observations=2,
            updated=1,
        )
    )

    correlation_mock.correlate.return_value = (
        expected_correlation
    )

    enrichment_mock.enrich.return_value = (
        _enrichment_result(
            records=2,
            persisted=1,
        )
    )

    _service(
        source=source,
        correlation=correlation,
        enrichment=enrichment,
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

    enrichment_mock.enrich \
        .assert_called_once_with(
            records=records,
            aggregates=(
                expected_correlation.aggregates
            ),
        )


def test_process_batch_handles_empty_source(
) -> None:
    source_mock, source = _source_mock()

    correlation_mock, correlation = (
        _correlation_mock()
    )

    enrichment_mock, enrichment = (
        _enrichment_mock()
    )

    source_mock.read_batch.return_value = ()

    expected_correlation = (
        _correlation_result(
            observations=0
        )
    )

    expected_enrichment = (
        _enrichment_result(
            records=0
        )
    )

    correlation_mock.correlate.return_value = (
        expected_correlation
    )

    enrichment_mock.enrich.return_value = (
        expected_enrichment
    )

    result = _service(
        source=source,
        correlation=correlation,
        enrichment=enrichment,
    ).process_batch(
        limit=50
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
        is expected_correlation
    )

    assert (
        result.cwe_enrichment
        is expected_enrichment
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
    source_mock, source = _source_mock()

    correlation_mock, correlation = (
        _correlation_mock()
    )

    enrichment_mock, enrichment = (
        _enrichment_mock()
    )

    service = _service(
        source=source,
        correlation=correlation,
        enrichment=enrichment,
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
    source_mock, source = _source_mock()

    correlation_mock, correlation = (
        _correlation_mock()
    )

    enrichment_mock, enrichment = (
        _enrichment_mock()
    )

    service = _service(
        source=source,
        correlation=correlation,
        enrichment=enrichment,
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
    source_mock, source = _source_mock()

    correlation_mock, correlation = (
        _correlation_mock()
    )

    enrichment_mock, enrichment = (
        _enrichment_mock()
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
            enrichment=enrichment,
        ).process_batch(
            limit=1
        )

    correlation_mock.correlate.assert_not_called()
    enrichment_mock.enrich.assert_not_called()


def test_process_batch_propagates_builder_failure(
) -> None:
    source_mock, source = _source_mock()

    correlation_mock, correlation = (
        _correlation_mock()
    )

    enrichment_mock, enrichment = (
        _enrichment_mock()
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
            cwe_enrichment_service=enrichment,
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


def test_process_batch_propagates_correlation_failure(
) -> None:
    source_mock, source = _source_mock()

    correlation_mock, correlation = (
        _correlation_mock()
    )

    enrichment_mock, enrichment = (
        _enrichment_mock()
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

    with pytest.raises(
        RuntimeError,
        match="correlation failure",
    ):
        _service(
            source=source,
            correlation=correlation,
            enrichment=enrichment,
        ).process_batch(
            limit=10
        )

    correlation_mock.correlate \
        .assert_called_once()

    enrichment_mock.enrich.assert_not_called()


def test_process_batch_propagates_enrichment_failure(
) -> None:
    source_mock, source = _source_mock()

    correlation_mock, correlation = (
        _correlation_mock()
    )

    enrichment_mock, enrichment = (
        _enrichment_mock()
    )

    records = (
        _record(
            normalized_record_id=_FIRST_ID,
            cve_id="CVE-2026-60001",
            day=4,
        ),
    )

    source_mock.read_batch.return_value = (
        records
    )

    expected_correlation = (
        _correlation_result(
            observations=1,
            created=1,
        )
    )

    correlation_mock.correlate.return_value = (
        expected_correlation
    )

    enrichment_mock.enrich.side_effect = (
        RuntimeError(
            "enrichment failure"
        )
    )

    with pytest.raises(
        RuntimeError,
        match="enrichment failure",
    ):
        _service(
            source=source,
            correlation=correlation,
            enrichment=enrichment,
        ).process_batch(
            limit=10
        )

    enrichment_mock.enrich \
        .assert_called_once_with(
            records=records,
            aggregates=(
                expected_correlation.aggregates
            ),
        )