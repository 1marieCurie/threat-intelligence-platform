from __future__ import annotations

import logging
from unittest.mock import Mock, call
from uuid import uuid4

import pytest

from application.services.github_advisory_normalization_service import (
    GitHubAdvisoryNormalizationResult,
)
from infrastructure.adapters.inbound.github_advisory_normalization_job import (
    GitHubAdvisoryNormalizationJob,
    GitHubAdvisoryNormalizationJobResult,
)


def _result(
    *,
    claimed: int = 0,
    normalized: int = 0,
    already_normalized: int = 0,
    failed: int = 0,
    requeued: int = 0,
    stale_failed: int = 0,
) -> GitHubAdvisoryNormalizationResult:
    return GitHubAdvisoryNormalizationResult(
        claimed=claimed,
        normalized=normalized,
        already_normalized=already_normalized,
        failed=failed,
        requeued=requeued,
        stale_failed=stale_failed,
    )


def test_constructor_rejects_missing_service(
) -> None:
    with pytest.raises(
        ValueError,
        match=(
            "normalization_service "
            "must not be None"
        ),
    ):
        GitHubAdvisoryNormalizationJob(
            normalization_service=(
                None
            ),  # type: ignore[arg-type]
            source_id=uuid4(),
            source_code="GITHUB_ADVISORY",
        )


def test_constructor_rejects_invalid_source_id(
) -> None:
    with pytest.raises(
        TypeError,
        match="source_id must be a UUID",
    ):
        GitHubAdvisoryNormalizationJob(
            normalization_service=Mock(),
            source_id=(
                "invalid"
            ),  # type: ignore[arg-type]
            source_code="GITHUB_ADVISORY",
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
        match=(
            "source_code must be a string"
        ),
    ):
        GitHubAdvisoryNormalizationJob(
            normalization_service=Mock(),
            source_id=uuid4(),
            source_code=(
                invalid_source_code
            ),  # type: ignore[arg-type]
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
        match=(
            "source_code must not be empty"
        ),
    ):
        GitHubAdvisoryNormalizationJob(
            normalization_service=Mock(),
            source_id=uuid4(),
            source_code=invalid_source_code,
        )


@pytest.mark.parametrize(
    (
        "field_name, invalid_value, "
        "error_type, message"
    ),
    [
        (
            "batch_size",
            True,
            TypeError,
            "batch_size must be an integer",
        ),
        (
            "batch_size",
            0,
            ValueError,
            (
                "batch_size must be "
                "greater than zero"
            ),
        ),
        (
            "max_batches",
            1.5,
            TypeError,
            "max_batches must be an integer",
        ),
        (
            "max_batches",
            -1,
            ValueError,
            (
                "max_batches must be "
                "greater than zero"
            ),
        ),
    ],
)
def test_constructor_rejects_invalid_limits(
    field_name: str,
    invalid_value: object,
    error_type: type[Exception],
    message: str,
) -> None:
    arguments: dict[str, object] = {
        "normalization_service": Mock(),
        "source_id": uuid4(),
        "source_code": "GITHUB_ADVISORY",
        field_name: invalid_value,
    }

    with pytest.raises(
        error_type,
        match=message,
    ):
        GitHubAdvisoryNormalizationJob(
            **arguments,  # type: ignore[arg-type]
        )


def test_run_stops_when_no_payload_is_claimed(
) -> None:
    source_id = uuid4()
    service = Mock()

    service.process_pending.return_value = (
        _result()
    )

    job = GitHubAdvisoryNormalizationJob(
        normalization_service=service,
        source_id=source_id,
        source_code="github_advisory",
        batch_size=25,
    )

    result = job.run()

    service.process_pending \
        .assert_called_once_with(
            source_id=source_id,
            limit=25,
        )

    assert result == (
        GitHubAdvisoryNormalizationJobResult(
            batches=0,
            claimed=0,
            normalized=0,
            already_normalized=0,
            failed=0,
            requeued=0,
            stale_failed=0,
        )
    )


def test_run_processes_batches_and_aggregates_results(
) -> None:
    source_id = uuid4()
    service = Mock()

    service.process_pending.side_effect = [
        _result(
            claimed=3,
            normalized=2,
            already_normalized=1,
            requeued=1,
        ),
        _result(
            claimed=2,
            normalized=1,
            failed=1,
            stale_failed=1,
        ),
        _result(
            requeued=2,
            stale_failed=1,
        ),
    ]

    job = GitHubAdvisoryNormalizationJob(
        normalization_service=service,
        source_id=source_id,
        source_code="GITHUB_ADVISORY",
        batch_size=3,
    )

    result = job.run()

    assert (
        service.process_pending.call_args_list
        == [
            call(
                source_id=source_id,
                limit=3,
            ),
            call(
                source_id=source_id,
                limit=3,
            ),
            call(
                source_id=source_id,
                limit=3,
            ),
        ]
    )

    assert result == (
        GitHubAdvisoryNormalizationJobResult(
            batches=2,
            claimed=5,
            normalized=3,
            already_normalized=1,
            failed=1,
            requeued=3,
            stale_failed=2,
        )
    )


def test_run_stops_after_first_empty_batch(
) -> None:
    service = Mock()

    service.process_pending.side_effect = [
        _result(
            claimed=2,
            normalized=2,
        ),
        _result(),
        _result(
            claimed=1,
            normalized=1,
        ),
    ]

    job = GitHubAdvisoryNormalizationJob(
        normalization_service=service,
        source_id=uuid4(),
        source_code="GITHUB_ADVISORY",
        batch_size=2,
    )

    result = job.run()

    assert (
        service.process_pending.call_count
        == 2
    )
    assert result.batches == 1
    assert result.claimed == 2
    assert result.normalized == 2


def test_run_counts_failed_payloads_without_stopping(
) -> None:
    service = Mock()

    service.process_pending.side_effect = [
        _result(
            claimed=3,
            normalized=1,
            failed=2,
        ),
        _result(),
    ]

    job = GitHubAdvisoryNormalizationJob(
        normalization_service=service,
        source_id=uuid4(),
        source_code="GITHUB_ADVISORY",
        batch_size=3,
    )

    result = job.run()

    assert result.batches == 1
    assert result.claimed == 3
    assert result.normalized == 1
    assert result.failed == 2


def test_run_logs_non_sensitive_completion_summary(
    caplog: pytest.LogCaptureFixture,
) -> None:
    source_id = uuid4()
    service = Mock()

    service.process_pending.side_effect = [
        _result(
            claimed=1,
            normalized=1,
        ),
        _result(),
    ]

    job = GitHubAdvisoryNormalizationJob(
        normalization_service=service,
        source_id=source_id,
        source_code="github_advisory",
    )

    with caplog.at_level(
        logging.INFO
    ):
        job.run()

    completed_record = next(
        record
        for record in caplog.records
        if record.getMessage()
        == (
            "GitHub Advisory "
            "normalization completed"
        )
    )

    assert (
        completed_record.__dict__[
            "source_code"
        ]
        == "GITHUB_ADVISORY"
    )

    assert (
        completed_record.__dict__[
            "source_id"
        ]
        == str(source_id)
    )

    assert (
        completed_record.__dict__[
            "batches"
        ]
        == 1
    )

    assert (
        completed_record.__dict__[
            "claimed"
        ]
        == 1
    )

    assert (
        completed_record.__dict__[
            "normalized"
        ]
        == 1
    )


def test_run_rejects_unbounded_processing_cycle(
) -> None:
    service = Mock()

    service.process_pending.return_value = (
        _result(
            claimed=1,
            normalized=1,
        )
    )

    job = GitHubAdvisoryNormalizationJob(
        normalization_service=service,
        source_id=uuid4(),
        source_code="GITHUB_ADVISORY",
        batch_size=1,
        max_batches=2,
    )

    with pytest.raises(
        RuntimeError,
        match=(
            "reached max_batches "
            "before completion"
        ),
    ):
        job.run()

    assert (
        service.process_pending.call_count
        == 2
    )


def test_run_redacts_failure_and_propagates_error(
    caplog: pytest.LogCaptureFixture,
) -> None:
    service = Mock()

    service.process_pending.side_effect = (
        RuntimeError(
            "api_key=super-secret-value"
        )
    )

    job = GitHubAdvisoryNormalizationJob(
        normalization_service=service,
        source_id=uuid4(),
        source_code="GITHUB_ADVISORY",
    )

    with caplog.at_level(
        logging.ERROR
    ):
        with pytest.raises(
            RuntimeError,
            match="super-secret-value",
        ):
            job.run()

    failure_record = next(
        record
        for record in caplog.records
        if record.getMessage()
        == (
            "GitHub Advisory "
            "normalization failed"
        )
    )

    error_summary = (
        failure_record.__dict__[
            "error_summary"
        ]
    )

    assert (
        "super-secret-value"
        not in error_summary
    )
    assert "[REDACTED]" in error_summary

    assert (
        "super-secret-value"
        not in caplog.text
    )

    assert failure_record.exc_info is None