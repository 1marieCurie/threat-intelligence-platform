from unittest.mock import Mock
from uuid import uuid4
import logging

import pytest

from application.services.ingestion_service import (
    IngestionResult,
)
from infrastructure.adapters.inbound.github_advisory_raw_ingestion_job import (
    GitHubAdvisoryRawIngestionJob,
)


def test_job_rejects_missing_service() -> None:
    with pytest.raises(
        ValueError,
        match="ingestion_service must not be None",
    ):
        GitHubAdvisoryRawIngestionJob(
            ingestion_service=None,  # type: ignore[arg-type]
            source_id=uuid4(),
        )


def test_job_rejects_invalid_source_id() -> None:
    ingestion_service = Mock()

    with pytest.raises(
        TypeError,
        match="source_id must be a UUID",
    ):
        GitHubAdvisoryRawIngestionJob(
            ingestion_service=ingestion_service,
            source_id="invalid-source-id",  # type: ignore[arg-type]
        )


def test_job_calls_ingestion_service_once() -> None:
    source_id = uuid4()
    ingestion_service = Mock()

    expected_result = IngestionResult(
        run_id=uuid4(),
        records_received=3,
        records_persisted=2,
        records_skipped=1,
        status="completed",
    )

    ingestion_service.ingest.return_value = expected_result

    job = GitHubAdvisoryRawIngestionJob(
        ingestion_service=ingestion_service,
        source_id=source_id,
    )

    job.run()

    ingestion_service.ingest.assert_called_once_with(
        source_id=source_id,
    )


def test_job_returns_ingestion_result() -> None:
    source_id = uuid4()
    ingestion_service = Mock()

    expected_result = IngestionResult(
        run_id=uuid4(),
        records_received=2,
        records_persisted=2,
        records_skipped=0,
        status="completed",
    )

    ingestion_service.ingest.return_value = expected_result

    job = GitHubAdvisoryRawIngestionJob(
        ingestion_service=ingestion_service,
        source_id=source_id,
    )

    result = job.run()

    assert result is expected_result


def test_job_logs_execution_summary(
    caplog: pytest.LogCaptureFixture,
) -> None:
    source_id = uuid4()

    ingestion_service = Mock()
    ingestion_service.ingest.return_value = (
        IngestionResult(
            run_id=uuid4(),
            records_received=100,
            records_persisted=90,
            records_skipped=10,
            status="completed",
            pagination_complete=False,
        )
    )

    job = GitHubAdvisoryRawIngestionJob(
        ingestion_service=ingestion_service,
        source_id=source_id,
    )

    with caplog.at_level(logging.INFO):
        result = job.run()

    assert result.records_received == 100

    messages = [
        record.getMessage()
        for record in caplog.records
    ]

    assert (
        "GitHub advisory raw ingestion started"
        in messages
    )
    assert (
        "GitHub advisory raw ingestion completed"
        in messages
    )

    completed_record = next(
        record
        for record in caplog.records
        if record.getMessage()
        == "GitHub advisory raw ingestion completed"
    )

    assert completed_record.__dict__["records_received"] == 100
    assert completed_record.__dict__["records_persisted"] == 90
    assert completed_record.__dict__["records_skipped"] == 10
    assert completed_record.__dict__["status"] == "completed"
    assert (
        completed_record.__dict__["pagination_complete"]
        is False
    )


def test_job_logs_failure_and_propagates_error(
    caplog: pytest.LogCaptureFixture,
) -> None:
    source_id = uuid4()

    ingestion_service = Mock()
    ingestion_service.ingest.side_effect = (
        RuntimeError(
            "GitHub API unavailable"
        )
    )

    job = GitHubAdvisoryRawIngestionJob(
        ingestion_service=ingestion_service,
        source_id=source_id,
    )

    with caplog.at_level(logging.ERROR):
        with pytest.raises(
            RuntimeError,
            match="GitHub API unavailable",
        ):
            job.run()

    failure_record = next(
        record
        for record in caplog.records
        if record.getMessage()
        == "GitHub advisory raw ingestion failed"
    )

    assert (
        failure_record.__dict__["source_id"]
        == str(source_id)
    )
    assert failure_record.exc_info is not None


def test_job_propagates_ingestion_error() -> None:
    source_id = uuid4()
    ingestion_service = Mock()

    ingestion_service.ingest.side_effect = RuntimeError(
        "GitHub ingestion failed",
    )

    job = GitHubAdvisoryRawIngestionJob(
        ingestion_service=ingestion_service,
        source_id=source_id,
    )

    with pytest.raises(
        RuntimeError,
        match="GitHub ingestion failed",
    ):
        job.run()

    ingestion_service.ingest.assert_called_once_with(
        source_id=source_id,
    )