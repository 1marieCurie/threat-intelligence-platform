from __future__ import annotations

import logging
from unittest.mock import Mock
from uuid import uuid4

import pytest

from application.services.ingestion_service import (
    IngestionResult,
)
from infrastructure.adapters.inbound.raw_ingestion_job import (
    RawIngestionJob,
)


def test_constructor_rejects_missing_service() -> None:
    with pytest.raises(
        ValueError,
        match="must not be None",
    ):
        RawIngestionJob(
            ingestion_service=None,  # type: ignore[arg-type]
            source_id=uuid4(),
            source_code="CISA_KEV",
        )


def test_constructor_rejects_invalid_source_id() -> None:
    with pytest.raises(
        TypeError,
        match="source_id must be a UUID",
    ):
        RawIngestionJob(
            ingestion_service=Mock(),
            source_id="invalid",  # type: ignore[arg-type]
            source_code="CISA_KEV",
        )


@pytest.mark.parametrize(
    "invalid_source_code",
    [
        None,
        123,
        True,
    ],
)
def test_constructor_rejects_non_string_source_code(
    invalid_source_code: object,
) -> None:
    with pytest.raises(
        TypeError,
        match="source_code must be a string",
    ):
        RawIngestionJob(
            ingestion_service=Mock(),
            source_id=uuid4(),
            source_code=invalid_source_code,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "invalid_source_code",
    [
        "",
        "   ",
    ],
)
def test_constructor_rejects_empty_source_code(
    invalid_source_code: str,
) -> None:
    with pytest.raises(
        ValueError,
        match="must not be empty",
    ):
        RawIngestionJob(
            ingestion_service=Mock(),
            source_id=uuid4(),
            source_code=invalid_source_code,
        )


def test_run_delegates_to_ingestion_service() -> None:
    source_id = uuid4()
    ingestion_service = Mock()

    expected_result = IngestionResult(
        run_id=uuid4(),
        records_received=10,
        records_persisted=8,
        records_skipped=2,
        status="completed",
    )

    ingestion_service.ingest.return_value = (
        expected_result
    )

    job = RawIngestionJob(
        ingestion_service=ingestion_service,
        source_id=source_id,
        source_code="cisa_kev",
    )

    result = job.run()

    ingestion_service.ingest.assert_called_once_with(
        source_id=source_id,
    )

    assert result is expected_result


def test_run_logs_execution_summary(
    caplog: pytest.LogCaptureFixture,
) -> None:
    source_id = uuid4()
    run_id = uuid4()

    ingestion_service = Mock()
    ingestion_service.ingest.return_value = (
        IngestionResult(
            run_id=run_id,
            records_received=100,
            records_persisted=90,
            records_skipped=10,
            status="completed",
        )
    )

    job = RawIngestionJob(
        ingestion_service=ingestion_service,
        source_id=source_id,
        source_code="CISA_KEV",
    )

    with caplog.at_level(logging.INFO):
        job.run()

    completed_record = next(
        record
        for record in caplog.records
        if record.getMessage()
        == "Raw ingestion completed"
    )

    assert (
        completed_record.__dict__["source_code"]
        == "CISA_KEV"
    )
    assert (
        completed_record.__dict__["source_id"]
        == str(source_id)
    )
    assert (
        completed_record.__dict__["run_id"]
        == str(run_id)
    )
    assert (
        completed_record.__dict__["records_persisted"]
        == 90
    )


def test_run_logs_failure_and_propagates_error(
    caplog: pytest.LogCaptureFixture,
) -> None:
    source_id = uuid4()
    ingestion_service = Mock()

    ingestion_service.ingest.side_effect = (
        RuntimeError(
            "CISA unavailable"
        )
    )

    job = RawIngestionJob(
        ingestion_service=ingestion_service,
        source_id=source_id,
        source_code="CISA_KEV",
    )

    with caplog.at_level(logging.ERROR):
        with pytest.raises(
            RuntimeError,
            match="CISA unavailable",
        ):
            job.run()

    failure_record = next(
        record
        for record in caplog.records
        if record.getMessage()
        == "Raw ingestion failed"
    )

    assert (
        failure_record.__dict__["source_code"]
        == "CISA_KEV"
    )
    assert failure_record.exc_info is not None