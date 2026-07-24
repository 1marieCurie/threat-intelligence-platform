from unittest.mock import Mock
from uuid import uuid4

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


def test_job_prints_execution_summary(
    capsys: pytest.CaptureFixture[str],
) -> None:
    source_id = uuid4()
    ingestion_service = Mock()

    ingestion_service.ingest.return_value = IngestionResult(
        run_id=uuid4(),
        records_received=5,
        records_persisted=3,
        records_skipped=2,
        status="completed",
    )

    job = GitHubAdvisoryRawIngestionJob(
        ingestion_service=ingestion_service,
        source_id=source_id,
    )

    job.run()

    captured = capsys.readouterr()

    assert (
        captured.out
        == (
            "GitHub advisory raw ingestion completed: "
            "received=5, "
            "persisted=3, "
            "skipped=2, "
            "status=completed\n"
        )
    )


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