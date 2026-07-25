import io
import logging
import sys
from collections.abc import Iterator
from typing import Any

import pytest

from infrastructure.logging.configuration import (
    SensitiveDataFormatter,
    SensitiveDataLoggingFilter,
    _resolve_log_level,
    configure_logging,
)


@pytest.fixture(autouse=True)
def restore_root_logger() -> Iterator[None]:
    root_logger = logging.getLogger()

    previous_handlers = (
        root_logger.handlers[:]
    )
    previous_level = root_logger.level

    yield

    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
        handler.close()

    for handler in previous_handlers:
        root_logger.addHandler(handler)

    root_logger.setLevel(previous_level)


def test_filter_redacts_message_arguments() -> None:
    record = logging.LogRecord(
        name="test",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg="Request failed: %s",
        args=(
            "Authorization: Bearer secret-token",
        ),
        exc_info=None,
    )

    logging_filter = (
        SensitiveDataLoggingFilter()
    )

    assert logging_filter.filter(record) is True
    assert (
        "secret-token"
        not in record.getMessage()
    )
    assert (
        "[REDACTED]"
        in record.getMessage()
    )


def test_filter_redacts_extra_attributes() -> None:
    record = logging.LogRecord(
        name="test",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg="Database failure",
        args=(),
        exc_info=None,
    )

    record.__dict__["database_url"] = (
        "postgresql://app:secret-password"
        "@localhost/database"
    )

    SensitiveDataLoggingFilter().filter(
        record
    )

    database_url = record.__dict__[
        "database_url"
    ]

    assert (
        "secret-password"
        not in database_url
    )
    assert (
        "[REDACTED]"
        in database_url
    )


def test_formatter_redacts_exception_text() -> None:
    formatter = SensitiveDataFormatter(
        fmt="%(levelname)s %(message)s",
    )

    try:
        raise RuntimeError(
            "GITHUB_TOKEN=secret-token"
        )
    except RuntimeError:
        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname=__file__,
            lineno=1,
            msg="Ingestion failed",
            args=(),
            exc_info=sys.exc_info(),
        )

    formatted = formatter.format(record)

    assert (
        "secret-token"
        not in formatted
    )
    assert (
        "GITHUB_TOKEN=[REDACTED]"
        in formatted
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (None, logging.INFO),
        ("", logging.INFO),
        ("info", logging.INFO),
        ("WARNING", logging.WARNING),
        ("error", logging.ERROR),
        ("CRITICAL", logging.CRITICAL),
        ("DEBUG", logging.DEBUG),
    ],
)
def test_resolve_log_level(
    value: str | None,
    expected: int,
) -> None:
    assert (
        _resolve_log_level(value)
        == expected
    )


def test_rejects_invalid_log_level() -> None:
    with pytest.raises(
        ValueError,
        match="LOG_LEVEL must be one of",
    ):
        _resolve_log_level("TRACE")


@pytest.mark.parametrize(
    "max_length",
    [
        True,
        1.5,
        "100",
        None,
    ],
)
def test_formatter_rejects_invalid_length_type(
    max_length: Any,
) -> None:
    with pytest.raises(
        TypeError,
        match="max_length must be an integer",
    ):
        SensitiveDataFormatter(
            max_length=max_length,
        )


def test_configure_logging_emits_sanitized_log(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stream = io.StringIO()

    monkeypatch.setenv(
        "LOG_LEVEL",
        "INFO",
    )

    configure_logging(
        stream=stream,
        force=True,
    )

    logger = logging.getLogger(
        "test.ingestion"
    )

    logger.error(
        "Connection failed: %s",
        (
            "postgresql://app:"
            "secret-password@localhost/database"
        ),
    )

    output = stream.getvalue()

    assert (
        "secret-password"
        not in output
    )
    assert "[REDACTED]" in output
    assert "level=ERROR" in output
    assert (
        "logger=test.ingestion"
        in output
    )

