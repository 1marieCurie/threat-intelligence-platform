from __future__ import annotations

import logging
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch
from uuid import UUID, uuid4

import pytest

from infrastructure.cli import (
    github_advisory_normalization
    as github_advisory_normalization_cli,
)
from infrastructure.cli.github_advisory_normalization import (
    _parse_arguments,
    _parse_source_id,
    main,
)


CLI_MODULE = (
    "infrastructure.cli."
    "github_advisory_normalization"
)


def _find_log_record(
    caplog: pytest.LogCaptureFixture,
    message: str,
) -> logging.LogRecord:
    return next(
        record
        for record in caplog.records
        if record.getMessage() == message
    )


def _build_job_result() -> SimpleNamespace:
    return SimpleNamespace(
        batches=12,
        claimed=1_200,
        normalized=1_190,
        already_normalized=5,
        failed=5,
        requeued=2,
        stale_failed=1,
    )


def test_env_file_uses_project_root() -> None:
    expected_project_root = (
        Path(
            github_advisory_normalization_cli
            .__file__
        )
        .resolve()
        .parents[2]
    )

    assert (
        github_advisory_normalization_cli
        .PROJECT_ROOT
        == expected_project_root
    )

    assert (
        github_advisory_normalization_cli
        .ENV_FILE
        == expected_project_root / ".env"
    )


def test_parse_arguments_reads_source_id(
) -> None:
    source_id = uuid4()

    arguments = _parse_arguments(
        [
            "--source-id",
            str(source_id),
        ]
    )

    assert arguments.source_id == str(
        source_id
    )


def test_parse_arguments_requires_source_id(
) -> None:
    with pytest.raises(
        SystemExit,
    ) as captured_error:
        _parse_arguments([])

    assert captured_error.value.code == 2


def test_parse_source_id_returns_uuid(
) -> None:
    source_id = uuid4()

    result = _parse_source_id(
        str(source_id)
    )

    assert isinstance(
        result,
        UUID,
    )

    assert result == source_id


def test_parse_source_id_rejects_invalid_value(
) -> None:
    with pytest.raises(
        ValueError,
        match=(
            "source-id must be a valid UUID"
        ),
    ):
        _parse_source_id(
            "invalid-source-id"
        )


def test_main_runs_normalization_and_prints_summary(
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    source_id = uuid4()
    expected_result = _build_job_result()

    job = Mock()
    job.run.return_value = expected_result

    with (
        patch(
            f"{CLI_MODULE}."
            "configure_logging",
        ) as configure_logging,
        patch(
            f"{CLI_MODULE}."
            "_parse_arguments",
            return_value=Namespace(
                source_id=str(source_id),
            ),
        ) as parse_arguments,
        patch(
            f"{CLI_MODULE}."
            "build_github_advisory_normalization_job",
            return_value=job,
        ) as build_job,
        patch(
            f"{CLI_MODULE}.perf_counter",
            side_effect=[
                100.0,
                102.345,
            ],
        ),
    ):
        with caplog.at_level(
            logging.INFO
        ):
            exit_code = main([])

    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""

    configure_logging.assert_called_once_with()

    parse_arguments.assert_called_once_with(
        []
    )

    build_job.assert_called_once_with(
        source_id=source_id,
    )

    job.run.assert_called_once_with()

    assert "batches=12" in captured.out
    assert "claimed=1200" in captured.out
    assert "normalized=1190" in captured.out

    assert (
        "already_normalized=5"
        in captured.out
    )

    assert "failed=5" in captured.out
    assert "requeued=2" in captured.out

    assert (
        "stale_failed=1"
        in captured.out
    )

    assert (
        "duration_seconds=2.345"
        in captured.out
    )

    completed_record = _find_log_record(
        caplog,
        (
            "GitHub Advisory normalization "
            "execution completed"
        ),
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
        == 12
    )

    assert (
        completed_record.__dict__[
            "claimed"
        ]
        == 1_200
    )

    assert (
        completed_record.__dict__[
            "normalized"
        ]
        == 1_190
    )

    assert (
        completed_record.__dict__[
            "already_normalized"
        ]
        == 5
    )

    assert (
        completed_record.__dict__[
            "failed"
        ]
        == 5
    )

    assert (
        completed_record.__dict__[
            "requeued"
        ]
        == 2
    )

    assert (
        completed_record.__dict__[
            "stale_failed"
        ]
        == 1
    )

    assert (
        completed_record.__dict__[
            "duration_seconds"
        ]
        == 2.345
    )

    assert completed_record.exc_info is None


def test_main_returns_error_for_invalid_source_id(
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    with (
        patch(
            f"{CLI_MODULE}."
            "configure_logging",
        ) as configure_logging,
        patch(
            f"{CLI_MODULE}."
            "_parse_arguments",
            return_value=Namespace(
                source_id="invalid",
            ),
        ) as parse_arguments,
        patch(
            f"{CLI_MODULE}."
            "build_github_advisory_normalization_job",
        ) as build_job,
    ):
        with caplog.at_level(
            logging.ERROR
        ):
            exit_code = main([])

    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""

    configure_logging.assert_called_once_with()

    parse_arguments.assert_called_once_with(
        []
    )

    build_job.assert_not_called()

    assert (
        "source-id must be a valid UUID"
        in captured.err
    )

    failure_record = _find_log_record(
        caplog,
        (
            "GitHub Advisory normalization "
            "execution failed"
        ),
    )

    assert (
        failure_record.__dict__[
            "error_type"
        ]
        == "ValueError"
    )

    assert failure_record.exc_info is None


def test_main_redacts_job_failure(
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    source_id = uuid4()

    job = Mock()

    job.run.side_effect = RuntimeError(
        "authorization: Bearer "
        "super-secret-github-token"
    )

    with (
        patch(
            f"{CLI_MODULE}."
            "configure_logging",
        ) as configure_logging,
        patch(
            f"{CLI_MODULE}."
            "_parse_arguments",
            return_value=Namespace(
                source_id=str(source_id),
            ),
        ) as parse_arguments,
        patch(
            f"{CLI_MODULE}."
            "build_github_advisory_normalization_job",
            return_value=job,
        ) as build_job,
    ):
        with caplog.at_level(
            logging.ERROR
        ):
            exit_code = main([])

    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""

    configure_logging.assert_called_once_with()

    parse_arguments.assert_called_once_with(
        []
    )

    build_job.assert_called_once_with(
        source_id=source_id,
    )

    job.run.assert_called_once_with()

    assert (
        "super-secret-github-token"
        not in captured.err
    )

    assert "[REDACTED]" in captured.err

    failure_record = _find_log_record(
        caplog,
        (
            "GitHub Advisory normalization "
            "execution failed"
        ),
    )

    assert (
        failure_record.__dict__[
            "error_type"
        ]
        == "RuntimeError"
    )

    error_summary = (
        failure_record.__dict__[
            "error_summary"
        ]
    )

    assert (
        "super-secret-github-token"
        not in error_summary
    )

    assert "[REDACTED]" in error_summary

    assert failure_record.exc_info is None

    assert (
        "super-secret-github-token"
        not in caplog.text
    )