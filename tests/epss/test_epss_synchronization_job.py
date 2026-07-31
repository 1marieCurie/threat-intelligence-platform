from __future__ import annotations

import logging
from datetime import date
from unittest.mock import Mock

import pytest

from application.services.epss_synchronization_service import (
    EPSSSynchronizationResult,
)
from infrastructure.adapters.inbound.epss_synchronization_job import (
    EPSSSynchronizationJob,
)


def _result(
    *,
    requested_cves: int = 3,
    fetched_scores: int = 2,
    submitted_scores: int = 2,
    missing_cves: tuple[str, ...] = (
        "CVE-2099-0001",
    ),
    requested_score_date: date | None = None,
) -> EPSSSynchronizationResult:
    return EPSSSynchronizationResult(
        requested_cves=requested_cves,
        fetched_scores=fetched_scores,
        submitted_scores=submitted_scores,
        missing_cves=missing_cves,
        requested_score_date=requested_score_date,
    )


def test_constructor_rejects_missing_service(
) -> None:
    with pytest.raises(
        ValueError,
        match=(
            "synchronization_service "
            "must not be None"
        ),
    ):
        EPSSSynchronizationJob(
            synchronization_service=None,  # type: ignore[arg-type]
        )


def test_run_delegates_to_service(
) -> None:
    service = Mock()
    expected_result = _result()

    service.synchronize.return_value = (
        expected_result
    )

    job = EPSSSynchronizationJob(
        synchronization_service=service,
    )

    cve_ids = [
        "CVE-2021-44228",
        "CVE-2024-3094",
    ]

    result = job.run(
        cve_ids
    )

    service.synchronize.assert_called_once_with(
        cve_ids,
        score_date=None,
    )

    assert result is expected_result


def test_run_passes_historical_score_date(
) -> None:
    service = Mock()
    score_date = date(
        2026,
        7,
        29,
    )

    expected_result = _result(
        requested_score_date=score_date,
    )

    service.synchronize.return_value = (
        expected_result
    )

    job = EPSSSynchronizationJob(
        synchronization_service=service,
    )

    cve_ids = [
        "CVE-2021-44228",
    ]

    result = job.run(
        cve_ids,
        score_date=score_date,
    )

    service.synchronize.assert_called_once_with(
        cve_ids,
        score_date=score_date,
    )

    assert result is expected_result


def test_run_accepts_generic_iterable(
) -> None:
    service = Mock()
    expected_result = _result(
        requested_cves=2,
        fetched_scores=2,
        submitted_scores=2,
        missing_cves=(),
    )

    service.synchronize.return_value = (
        expected_result
    )

    job = EPSSSynchronizationJob(
        synchronization_service=service,
    )

    cve_ids = (
        cve_id
        for cve_id in (
            "CVE-2021-44228",
            "CVE-2024-3094",
        )
    )

    result = job.run(
        cve_ids
    )

    service.synchronize.assert_called_once_with(
        cve_ids,
        score_date=None,
    )

    assert result is expected_result


def test_run_logs_completion_counters(
    caplog: pytest.LogCaptureFixture,
) -> None:
    service = Mock()

    service.synchronize.return_value = (
        _result(
            requested_cves=5,
            fetched_scores=3,
            submitted_scores=3,
            missing_cves=(
                "CVE-2099-0001",
                "CVE-2099-0002",
            ),
        )
    )

    job = EPSSSynchronizationJob(
        synchronization_service=service,
    )

    with caplog.at_level(
        logging.INFO
    ):
        result = job.run(
            [
                "CVE-2021-44228",
                "CVE-2024-3094",
            ]
        )

    assert result.requested_cves == 5
    assert result.fetched_scores == 3
    assert result.submitted_scores == 3

    completed_record = next(
        record
        for record in caplog.records
        if record.getMessage()
        == "EPSS synchronization completed"
    )

    assert (
        completed_record.__dict__[
            "requested_cves"
        ]
        == 5
    )

    assert (
        completed_record.__dict__[
            "fetched_scores"
        ]
        == 3
    )

    assert (
        completed_record.__dict__[
            "submitted_scores"
        ]
        == 3
    )

    assert (
        completed_record.__dict__[
            "missing_cves_count"
        ]
        == 2
    )

    assert (
        completed_record.__dict__[
            "historical_sync"
        ]
        is False
    )

    assert (
        completed_record.__dict__[
            "requested_score_date"
        ]
        is None
    )


def test_run_does_not_log_cve_identifiers(
    caplog: pytest.LogCaptureFixture,
) -> None:
    service = Mock()

    requested_cve = (
        "CVE-2021-44228"
    )

    missing_cve = (
        "CVE-2099-987654"
    )

    service.synchronize.return_value = (
        _result(
            requested_cves=2,
            fetched_scores=1,
            submitted_scores=1,
            missing_cves=(
                missing_cve,
            ),
        )
    )

    job = EPSSSynchronizationJob(
        synchronization_service=service,
    )

    with caplog.at_level(
        logging.INFO
    ):
        job.run(
            [
                requested_cve,
                missing_cve,
            ]
        )

    assert requested_cve not in caplog.text
    assert missing_cve not in caplog.text

    completed_record = next(
        record
        for record in caplog.records
        if record.getMessage()
        == "EPSS synchronization completed"
    )

    assert (
        completed_record.__dict__[
            "missing_cves_count"
        ]
        == 1
    )


def test_run_logs_historical_synchronization(
    caplog: pytest.LogCaptureFixture,
) -> None:
    service = Mock()

    score_date = date(
        2026,
        7,
        29,
    )

    service.synchronize.return_value = (
        _result(
            requested_cves=1,
            fetched_scores=1,
            submitted_scores=1,
            missing_cves=(),
            requested_score_date=score_date,
        )
    )

    job = EPSSSynchronizationJob(
        synchronization_service=service,
    )

    with caplog.at_level(
        logging.INFO
    ):
        job.run(
            [
                "CVE-2021-44228",
            ],
            score_date=score_date,
        )

    started_record = next(
        record
        for record in caplog.records
        if record.getMessage()
        == "EPSS synchronization started"
    )

    assert (
        started_record.__dict__[
            "historical_sync"
        ]
        is True
    )

    assert (
        started_record.__dict__[
            "requested_score_date"
        ]
        == "2026-07-29"
    )

    completed_record = next(
        record
        for record in caplog.records
        if record.getMessage()
        == "EPSS synchronization completed"
    )

    assert (
        completed_record.__dict__[
            "historical_sync"
        ]
        is True
    )

    assert (
        completed_record.__dict__[
            "requested_score_date"
        ]
        == "2026-07-29"
    )


def test_run_logs_empty_synchronization(
    caplog: pytest.LogCaptureFixture,
) -> None:
    service = Mock()

    service.synchronize.return_value = (
        EPSSSynchronizationResult(
            requested_cves=0,
            fetched_scores=0,
            submitted_scores=0,
            missing_cves=(),
            requested_score_date=None,
        )
    )

    job = EPSSSynchronizationJob(
        synchronization_service=service,
    )

    with caplog.at_level(
        logging.INFO
    ):
        result = job.run(
            []
        )

    assert result.requested_cves == 0
    assert result.fetched_scores == 0
    assert result.submitted_scores == 0
    assert result.missing_cves == ()

    completed_record = next(
        record
        for record in caplog.records
        if record.getMessage()
        == "EPSS synchronization completed"
    )

    assert (
        completed_record.__dict__[
            "missing_cves_count"
        ]
        == 0
    )


def test_run_redacts_failure_and_propagates(
    caplog: pytest.LogCaptureFixture,
) -> None:
    service = Mock()

    secret = (
        "super-secret-password"
    )

    sensitive_cve = (
        "CVE-2021-44228"
    )

    service.synchronize.side_effect = (
        RuntimeError(
            "DATABASE_URL="
            "postgresql://user:"
            f"{secret}@localhost/db "
            f"while processing {sensitive_cve}"
        )
    )

    job = EPSSSynchronizationJob(
        synchronization_service=service,
    )

    with caplog.at_level(
        logging.ERROR
    ):
        with pytest.raises(
            RuntimeError,
            match=secret,
        ):
            job.run(
                [
                    sensitive_cve,
                ]
            )

    failure_record = next(
        record
        for record in caplog.records
        if record.getMessage()
        == "EPSS synchronization failed"
    )

    error_summary = (
        failure_record.__dict__[
            "error_summary"
        ]
    )

    assert (
        failure_record.__dict__[
            "error_type"
        ]
        == "RuntimeError"
    )

    assert secret not in error_summary
    assert sensitive_cve not in error_summary

    assert "[REDACTED]" in error_summary
    assert "[CVE_REDACTED]" in error_summary

    assert secret not in caplog.text
    assert sensitive_cve not in caplog.text

    assert failure_record.exc_info is None
    

def test_run_propagates_provider_failure(
) -> None:
    service = Mock()

    expected_error = RuntimeError(
        "FIRST EPSS API unavailable"
    )

    service.synchronize.side_effect = (
        expected_error
    )

    job = EPSSSynchronizationJob(
        synchronization_service=service,
    )

    with pytest.raises(
        RuntimeError,
        match="FIRST EPSS API unavailable",
    ) as raised_error:
        job.run(
            [
                "CVE-2021-44228",
            ]
        )

    assert (
        raised_error.value
        is expected_error
    )


def test_run_propagates_repository_failure(
) -> None:
    service = Mock()

    expected_error = RuntimeError(
        "PostgreSQL persistence failed"
    )

    service.synchronize.side_effect = (
        expected_error
    )

    job = EPSSSynchronizationJob(
        synchronization_service=service,
    )

    with pytest.raises(
        RuntimeError,
        match="PostgreSQL persistence failed",
    ) as raised_error:
        job.run(
            [
                "CVE-2021-44228",
            ]
        )

    assert (
        raised_error.value
        is expected_error
    )