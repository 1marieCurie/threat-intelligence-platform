import logging
from argparse import Namespace
from types import SimpleNamespace
from typing import Any
from unittest.mock import Mock, call, patch
from uuid import UUID, uuid4

import pytest

from infrastructure.cli.github_advisory_ingestion import (
    MAX_ALLOWED_PAGES,
    _parse_source_id,
    _validate_max_pages,
    main,
)


CLI_MODULE = (
    "infrastructure.cli."
    "github_advisory_ingestion"
)


def _build_ingestion_result(
    *,
    received: int,
    persisted: int,
    skipped: int,
    pagination_complete: bool,
) -> SimpleNamespace:
    return SimpleNamespace(
        records_received=received,
        records_persisted=persisted,
        records_skipped=skipped,
        pagination_complete=pagination_complete,
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


@pytest.mark.parametrize(
    "value",
    [
        1,
        10,
        MAX_ALLOWED_PAGES,
    ],
)
def test_validate_max_pages_accepts_valid_values(
    value: int,
) -> None:
    assert _validate_max_pages(value) == value


@pytest.mark.parametrize(
    ("value", "expected_message"),
    [
        (
            0,
            (
                "max-pages must be greater "
                "than or equal to 1"
            ),
        ),
        (
            -1,
            (
                "max-pages must be greater "
                "than or equal to 1"
            ),
        ),
        (
            MAX_ALLOWED_PAGES + 1,
            (
                "max-pages must be less than "
                "or equal to"
            ),
        ),
    ],
)
def test_validate_max_pages_rejects_out_of_range_values(
    value: int,
    expected_message: str,
) -> None:
    with pytest.raises(
        ValueError,
        match=expected_message,
    ):
        _validate_max_pages(value)


@pytest.mark.parametrize(
    "value",
    [
        True,
        False,
        1.5,
        "10",
        None,
    ],
)
def test_validate_max_pages_rejects_non_integer_values(
    value: Any,
) -> None:
    with pytest.raises(
        TypeError,
        match="max-pages must be an integer",
    ):
        _validate_max_pages(value)


@patch(
    f"{CLI_MODULE}.configure_logging"
)
@patch(
    f"{CLI_MODULE}."
    "build_github_advisory_ingestion_job"
)
@patch(
    f"{CLI_MODULE}._parse_arguments"
)
@patch(
    f"{CLI_MODULE}.load_dotenv"
)
@patch(
    f"{CLI_MODULE}.find_dotenv"
)
def test_main_processes_requested_number_of_pages(
    find_dotenv: Mock,
    load_dotenv: Mock,
    parse_arguments: Mock,
    build_job: Mock,
    configure_logging: Mock,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    source_id = uuid4()

    find_dotenv.return_value = (
        "C:/project/.env"
    )

    parse_arguments.return_value = Namespace(
        source_id=str(source_id),
        max_pages=3,
    )

    job = Mock()
    job.run.side_effect = [
        _build_ingestion_result(
            received=100,
            persisted=100,
            skipped=0,
            pagination_complete=False,
        ),
        _build_ingestion_result(
            received=100,
            persisted=90,
            skipped=10,
            pagination_complete=False,
        ),
        _build_ingestion_result(
            received=50,
            persisted=40,
            skipped=10,
            pagination_complete=False,
        ),
    ]

    build_job.return_value = job

    with caplog.at_level(logging.INFO):
        exit_code = main()

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

    build_job.assert_called_once_with(
        source_id=source_id,
    )

    assert job.run.call_count == 3
    assert job.run.call_args_list == [
        call(),
        call(),
        call(),
    ]

    assert "pages=3" in captured.out
    assert "received=250" in captured.out
    assert "persisted=230" in captured.out
    assert "skipped=20" in captured.out

    assert (
        "pagination_complete=False"
        in captured.out
    )
    assert (
        "stop_reason=max_pages_reached"
        in captured.out
    )

    assert captured.err == ""

    started_record = _find_log_record(
        caplog,
        (
            "GitHub advisory ingestion "
            "cycle started"
        ),
    )

    assert (
        started_record.__dict__["source_id"]
        == str(source_id)
    )
    assert (
        started_record.__dict__["max_pages"]
        == 3
    )

    completed_record = _find_log_record(
        caplog,
        (
            "GitHub advisory ingestion "
            "cycle completed"
        ),
    )

    assert (
        completed_record.levelno
        == logging.WARNING
    )
    assert (
        completed_record.__dict__[
            "pages_processed"
        ]
        == 3
    )
    assert (
        completed_record.__dict__[
            "stop_reason"
        ]
        == "max_pages_reached"
    )
    assert (
        completed_record.__dict__[
            "records_received"
        ]
        == 250
    )
    assert (
        completed_record.__dict__[
            "records_persisted"
        ]
        == 230
    )
    assert (
        completed_record.__dict__[
            "records_skipped"
        ]
        == 20
    )
    assert (
        completed_record.__dict__[
            "pagination_complete"
        ]
        is False
    )
    assert isinstance(
        completed_record.__dict__[
            "duration_seconds"
        ],
        float,
    )


@patch(
    f"{CLI_MODULE}.configure_logging"
)
@patch(
    f"{CLI_MODULE}."
    "build_github_advisory_ingestion_job"
)
@patch(
    f"{CLI_MODULE}._parse_arguments"
)
@patch(
    f"{CLI_MODULE}.load_dotenv"
)
@patch(
    f"{CLI_MODULE}.find_dotenv"
)
def test_main_stops_when_pagination_is_complete(
    find_dotenv: Mock,
    load_dotenv: Mock,
    parse_arguments: Mock,
    build_job: Mock,
    configure_logging: Mock,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    source_id = uuid4()

    find_dotenv.return_value = ".env"

    parse_arguments.return_value = Namespace(
        source_id=str(source_id),
        max_pages=10,
    )

    job = Mock()
    job.run.side_effect = [
        _build_ingestion_result(
            received=100,
            persisted=100,
            skipped=0,
            pagination_complete=False,
        ),
        _build_ingestion_result(
            received=25,
            persisted=20,
            skipped=5,
            pagination_complete=True,
        ),
    ]

    build_job.return_value = job

    with caplog.at_level(logging.INFO):
        exit_code = main()

    captured = capsys.readouterr()

    assert exit_code == 0
    assert job.run.call_count == 2

    assert "pages=2" in captured.out
    assert "received=125" in captured.out
    assert "persisted=120" in captured.out
    assert "skipped=5" in captured.out

    assert (
        "pagination_complete=True"
        in captured.out
    )
    assert (
        "stop_reason=pagination_complete"
        in captured.out
    )

    assert captured.err == ""

    load_dotenv.assert_called_once_with(
        dotenv_path=".env",
        override=False,
    )

    configure_logging.assert_called_once_with()

    completed_record = _find_log_record(
        caplog,
        (
            "GitHub advisory ingestion "
            "cycle completed"
        ),
    )

    assert (
        completed_record.levelno
        == logging.INFO
    )
    assert (
        completed_record.__dict__[
            "pages_processed"
        ]
        == 2
    )
    assert (
        completed_record.__dict__[
            "stop_reason"
        ]
        == "pagination_complete"
    )
    assert (
        completed_record.__dict__[
            "records_received"
        ]
        == 125
    )
    assert (
        completed_record.__dict__[
            "records_persisted"
        ]
        == 120
    )
    assert (
        completed_record.__dict__[
            "records_skipped"
        ]
        == 5
    )
    assert (
        completed_record.__dict__[
            "pagination_complete"
        ]
        is True
    )


@patch(
    f"{CLI_MODULE}.configure_logging"
)
@patch(
    f"{CLI_MODULE}."
    "build_github_advisory_ingestion_job"
)
@patch(
    f"{CLI_MODULE}._parse_arguments"
)
@patch(
    f"{CLI_MODULE}.load_dotenv"
)
@patch(
    f"{CLI_MODULE}.find_dotenv"
)
def test_main_uses_single_page_by_default(
    find_dotenv: Mock,
    load_dotenv: Mock,
    parse_arguments: Mock,
    build_job: Mock,
    configure_logging: Mock,
) -> None:
    source_id = uuid4()

    find_dotenv.return_value = ".env"

    parse_arguments.return_value = Namespace(
        source_id=str(source_id),
        max_pages=1,
    )

    job = Mock()
    job.run.return_value = (
        _build_ingestion_result(
            received=100,
            persisted=100,
            skipped=0,
            pagination_complete=False,
        )
    )

    build_job.return_value = job

    exit_code = main()

    assert exit_code == 0

    configure_logging.assert_called_once_with()
    job.run.assert_called_once_with()


@patch(
    f"{CLI_MODULE}.configure_logging"
)
@patch(
    f"{CLI_MODULE}."
    "build_github_advisory_ingestion_job"
)
@patch(
    f"{CLI_MODULE}._parse_arguments"
)
@patch(
    f"{CLI_MODULE}.load_dotenv"
)
@patch(
    f"{CLI_MODULE}.find_dotenv"
)
def test_main_returns_error_code_when_job_fails(
    find_dotenv: Mock,
    load_dotenv: Mock,
    parse_arguments: Mock,
    build_job: Mock,
    configure_logging: Mock,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    source_id = uuid4()

    find_dotenv.return_value = ".env"

    parse_arguments.return_value = Namespace(
        source_id=str(source_id),
        max_pages=5,
    )

    job = Mock()
    job.run.side_effect = RuntimeError(
        "Authorization: Bearer ghp_secret_value "
        "GITHUB_TOKEN=another_secret "
        "postgresql://app:"
        "db_password@localhost/database"
    )

    build_job.return_value = job

    with caplog.at_level(logging.ERROR):
        exit_code = main()

    captured = capsys.readouterr()

    assert exit_code == 1
    job.run.assert_called_once_with()

    configure_logging.assert_called_once_with()

    assert captured.out == ""

    assert (
        "ghp_secret_value"
        not in captured.err
    )
    assert (
        "another_secret"
        not in captured.err
    )
    assert (
        "db_password"
        not in captured.err
    )

    assert (
        "Authorization: [REDACTED]"
        in captured.err
    )
    assert (
        "GITHUB_TOKEN=[REDACTED]"
        in captured.err
    )
    assert (
        "postgresql://app:"
        "[REDACTED]@localhost/database"
        in captured.err
    )

    assert (
        "GitHub advisory ingestion failed:"
        in captured.err
    )

    failure_record = _find_log_record(
        caplog,
        (
            "GitHub advisory ingestion "
            "cycle failed"
        ),
    )

    assert (
        failure_record.levelno
        == logging.ERROR
    )
    assert (
        failure_record.__dict__["error_type"]
        == "RuntimeError"
    )

    error_message = (
        failure_record.__dict__[
            "error_message"
        ]
    )

    assert (
        "ghp_secret_value"
        not in error_message
    )
    assert (
        "another_secret"
        not in error_message
    )
    assert (
        "db_password"
        not in error_message
    )
    assert "[REDACTED]" in error_message


@patch(
    f"{CLI_MODULE}.configure_logging"
)
@patch(
    f"{CLI_MODULE}."
    "build_github_advisory_ingestion_job"
)
@patch(
    f"{CLI_MODULE}._parse_arguments"
)
@patch(
    f"{CLI_MODULE}.load_dotenv"
)
@patch(
    f"{CLI_MODULE}.find_dotenv"
)
def test_main_rejects_invalid_source_id(
    find_dotenv: Mock,
    load_dotenv: Mock,
    parse_arguments: Mock,
    build_job: Mock,
    configure_logging: Mock,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    find_dotenv.return_value = ".env"

    parse_arguments.return_value = Namespace(
        source_id="invalid-source-id",
        max_pages=1,
    )

    with caplog.at_level(logging.ERROR):
        exit_code = main()

    captured = capsys.readouterr()

    assert exit_code == 1

    configure_logging.assert_called_once_with()
    build_job.assert_not_called()

    assert (
        "source-id must be a valid UUID"
        in captured.err
    )

    failure_record = _find_log_record(
        caplog,
        (
            "GitHub advisory ingestion "
            "cycle failed"
        ),
    )

    assert (
        failure_record.__dict__["error_type"]
        == "ValueError"
    )


@patch(
    f"{CLI_MODULE}.configure_logging"
)
@patch(
    f"{CLI_MODULE}."
    "build_github_advisory_ingestion_job"
)
@patch(
    f"{CLI_MODULE}._parse_arguments"
)
@patch(
    f"{CLI_MODULE}.load_dotenv"
)
@patch(
    f"{CLI_MODULE}.find_dotenv"
)
def test_main_rejects_invalid_max_pages(
    find_dotenv: Mock,
    load_dotenv: Mock,
    parse_arguments: Mock,
    build_job: Mock,
    configure_logging: Mock,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    find_dotenv.return_value = ".env"

    parse_arguments.return_value = Namespace(
        source_id=str(uuid4()),
        max_pages=0,
    )

    with caplog.at_level(logging.ERROR):
        exit_code = main()

    captured = capsys.readouterr()

    assert exit_code == 1

    configure_logging.assert_called_once_with()
    build_job.assert_not_called()

    assert (
        "max-pages must be greater than "
        "or equal to 1"
        in captured.err
    )

    failure_record = _find_log_record(
        caplog,
        (
            "GitHub advisory ingestion "
            "cycle failed"
        ),
    )

    assert (
        failure_record.__dict__["error_type"]
        == "ValueError"
    )

