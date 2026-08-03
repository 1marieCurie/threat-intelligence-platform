from __future__ import annotations

import logging
import os
import sys
from collections.abc import Mapping
from typing import Any, TextIO

from pathlib import Path
from dotenv import load_dotenv

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)

ENV_FILE = PROJECT_ROOT / ".env"

load_dotenv(
    dotenv_path=ENV_FILE,
    override=False,
)



from application.security.sensitive_data_redactor import (
    redact_sensitive_data,
)


DEFAULT_LOG_LEVEL = "INFO"
DEFAULT_LOG_MAX_LENGTH = 4_000

_ALLOWED_LOG_LEVELS: dict[str, int] = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL,
}


class SensitiveDataLoggingFilter(logging.Filter):
    def filter(
        self,
        record: logging.LogRecord,
    ) -> bool:
        record.msg = _sanitize_log_value(
            record.msg
        )

        if record.args:
            record.args = _sanitize_log_arguments(
                record.args
            )

        _sanitize_extra_attributes(record)

        return True


class SensitiveDataFormatter(logging.Formatter):
    def __init__(
        self,
        fmt: str | None = None,
        datefmt: str | None = None,
        *,
        max_length: int = DEFAULT_LOG_MAX_LENGTH,
    ) -> None:
        super().__init__(
            fmt=fmt,
            datefmt=datefmt,
        )

        if isinstance(max_length, bool) or not isinstance(
            max_length,
            int,
        ):
            raise TypeError(
                "max_length must be an integer"
            )

        if max_length < 1:
            raise ValueError(
                "max_length must be greater than or equal to 1"
            )

        self._max_length = max_length

    def format(
        self,
        record: logging.LogRecord,
    ) -> str:
        formatted = super().format(record)

        return redact_sensitive_data(
            formatted,
            max_length=self._max_length,
        )


def configure_logging(
    *,
    level: str | None = None,
    stream: TextIO | None = None,
    force: bool = True,
) -> None:
    

    resolved_level = _resolve_log_level(
        level or os.getenv("LOG_LEVEL")
    )

    handler = logging.StreamHandler(
        stream or sys.stderr
    )

    handler.addFilter(
        SensitiveDataLoggingFilter()
    )

    handler.setFormatter(
        SensitiveDataFormatter(
            fmt=(
                "%(asctime)s "
                "level=%(levelname)s "
                "logger=%(name)s "
                "message=%(message)s"
            ),
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )
    )

    root_logger = logging.getLogger()

    if force:
        for existing_handler in (
            root_logger.handlers[:]
        ):
            root_logger.removeHandler(
                existing_handler
            )
            existing_handler.close()

    root_logger.setLevel(resolved_level)
    root_logger.addHandler(handler)


def _resolve_log_level(
    value: str | None,
) -> int:
    if value is None:
        return logging.INFO

    normalized = value.strip().upper()

    if not normalized:
        return logging.INFO

    try:
        return _ALLOWED_LOG_LEVELS[
            normalized
        ]
    except KeyError as error:
        raise ValueError(
            "LOG_LEVEL must be one of: "
            + ", ".join(
                _ALLOWED_LOG_LEVELS
            )
        ) from error


def _sanitize_log_arguments(
    arguments: tuple[Any, ...] | Mapping[str, Any],
) -> tuple[Any, ...] | dict[str, Any]:
    if isinstance(arguments, Mapping):
        return {
            key: _sanitize_log_value(value)
            for key, value in arguments.items()
        }

    return tuple(
        _sanitize_log_value(value)
        for value in arguments
    )


def _sanitize_log_value(
    value: Any,
) -> Any:
    if isinstance(value, str):
        return redact_sensitive_data(
            value,
            max_length=DEFAULT_LOG_MAX_LENGTH,
        )

    return value


def _sanitize_extra_attributes(
    record: logging.LogRecord,
) -> None:
    standard_attributes = logging.LogRecord(
        name="",
        level=0,
        pathname="",
        lineno=0,
        msg="",
        args=(),
        exc_info=None,
    ).__dict__

    for key, value in tuple(
        record.__dict__.items()
    ):
        if key in standard_attributes:
            continue

        if isinstance(value, str):
            record.__dict__[key] = (
                redact_sensitive_data(
                    value,
                    max_length=(
                        DEFAULT_LOG_MAX_LENGTH
                    ),
                )
            )
