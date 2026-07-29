from __future__ import annotations

import logging
from argparse import Namespace
from types import SimpleNamespace
from unittest.mock import Mock, patch
from uuid import UUID, uuid4

import pytest

from infrastructure.cli.cisa_kev_normalization import (
    _parse_arguments,
    _parse_source_id,
    main,
)


CLI_MODULE = (
    "infrastructure.cli."
    "cisa_kev_normalization"
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
        batches=17,
        claimed=1_655,
        normalized=1_650,
        already_normalized=3,
        failed=2,
        requeued=4,
        stale_failed=1,
    )


def test_parse_arguments_reads_source_id() -> None:
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


def test_parse_arguments_requires_source_id() -> None:
    with pytest.raises(
        SystemExit,
    ) as captured_error:
        _parse_arguments([])

    assert captured_error.value.code == 2


def test_parse_source_id_returns_uuid() -> None:
    source_id = uuid4()

    result = _parse_source_id(
        str(source_id)
    )

    assert isinstance(result, UUID)
    assert result == source_id


def test_parse_source_id_rejects_invalid_value() -> None:
    with pytest.raises(
        ValueError,
        match="source-id must be a valid UUID",
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
            f"{CLI_MODULE}.find_dotenv",
            return_value="C:/project/.env",
        ) as find_dotenv,
        patch(
            f"{CLI_MODULE}.load_dotenv",
        ) as load_dotenv,
        patch(
            f"{CLI_MODULE}.configure_logging",
        ) as configure_logging,
        patch(
            f"{CLI_MODULE}._parse_arguments",
            return_value=Namespace(
                source_id=str(source_id),
            ),
        ) as parse_arguments,
        patch(
            f"{CLI_MODULE}."
            "build_cisa_kev_normalization_job",
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
        with caplog.at_level(logging.INFO):
            exit_code = main([])

    captured = capsys.readouterr()

    assert exit_code == 0

    find_dotenv.assert_called_once_with(
        usecwd=True
    )

    load_dotenv.assert_called_once_with(
        dotenv_path="C:/project/.env",
        override=False,
    )

    configure_logging.assert_called_once_with()

    parse_arguments.assert_called_once_with(
        []
    )

    build_job.assert_called_once_with(
        source_id=source_id,
    )

    job.run.assert_called_once_with()

    assert "batches=17" in captured.out
    assert "claimed=1655" in captured.out
    assert "normalized=1650" in captured.out

    assert (
        "already_normalized=3"
        in captured.out
    )

    assert "failed=2" in captured.out
    assert "requeued=4" in captured.out
    assert "stale_failed=1" in captured.out

    assert (
        "duration_seconds=2.345"
        in captured.out
    )

    assert captured.err == ""

    completed_record = _find_log_record(
        caplog,
        (
            "CISA KEV normalization "
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
        == 17
    )
    assert (
        completed_record.__dict__[
            "claimed"
        ]
        == 1_655
    )
    assert (
        completed_record.__dict__[
            "normalized"
        ]
        == 1_650
    )
    assert (
        completed_record.__dict__[
            "failed"
        ]
        == 2
    )
    assert (
        completed_record.__dict__[
            "duration_seconds"
        ]
        == 2.345
    )


def test_main_returns_error_for_invalid_source_id(
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    with (
        patch(
            f"{CLI_MODULE}.find_dotenv",
            return_value=".env",
        ),
        patch(
            f"{CLI_MODULE}.load_dotenv",
        ),
        patch(
            f"{CLI_MODULE}.configure_logging",
        ),
        patch(
            f"{CLI_MODULE}._parse_arguments",
            return_value=Namespace(
                source_id="invalid",
            ),
        ),
        patch(
            f"{CLI_MODULE}."
            "build_cisa_kev_normalization_job",
        ) as build_job,
    ):
        with caplog.at_level(logging.ERROR):
            exit_code = main([])

    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""

    assert (
        "source-id must be a valid UUID"
        in captured.err
    )

    build_job.assert_not_called()

    failure_record = _find_log_record(
        caplog,
        (
            "CISA KEV normalization "
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
        "api_key=super-secret-value"
    )

    with (
        patch(
            f"{CLI_MODULE}.find_dotenv",
            return_value=".env",
        ),
        patch(
            f"{CLI_MODULE}.load_dotenv",
        ),
        patch(
            f"{CLI_MODULE}.configure_logging",
        ),
        patch(
            f"{CLI_MODULE}._parse_arguments",
            return_value=Namespace(
                source_id=str(source_id),
            ),
        ),
        patch(
            f"{CLI_MODULE}."
            "build_cisa_kev_normalization_job",
            return_value=job,
        ),
    ):
        with caplog.at_level(logging.ERROR):
            exit_code = main([])

    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""

    assert (
        "super-secret-value"
        not in captured.err
    )
    assert "[REDACTED]" in captured.err

    failure_record = _find_log_record(
        caplog,
        (
            "CISA KEV normalization "
            "execution failed"
        ),
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

    assert failure_record.exc_info is None
    assert "super-secret-value" not in caplog.text