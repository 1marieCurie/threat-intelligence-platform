from __future__ import annotations

import argparse
import logging
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from time import perf_counter
from uuid import UUID

from dotenv import load_dotenv

from infrastructure.bootstrap.urlhaus_normalization import (
    URLHAUS_NORMALIZATION_BATCH_SIZE_ENV,
    URLHAUS_NORMALIZATION_LEASE_TIMEOUT_SECONDS_ENV,
    URLHAUS_NORMALIZATION_MAX_ATTEMPTS_ENV,
    URLHAUS_NORMALIZATION_MAX_BATCHES_ENV,
    build_urlhaus_normalization_job,
)
from infrastructure.logging.configuration import (
    configure_logging,
)


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


logger = logging.getLogger(__name__)


URLHAUS_SOURCE_ID_ENV = (
    "URLHAUS_SOURCE_ID"
)

_SAFE_CONFIGURATION_VARIABLES = frozenset(
    {
        URLHAUS_NORMALIZATION_BATCH_SIZE_ENV,
        URLHAUS_NORMALIZATION_LEASE_TIMEOUT_SECONDS_ENV,
        URLHAUS_NORMALIZATION_MAX_ATTEMPTS_ENV,
        URLHAUS_NORMALIZATION_MAX_BATCHES_ENV,
    }
)

_SAFE_CONFIGURATION_SUFFIXES = (
    "must not be empty",
    "must be an integer",
    "must be greater than zero",
    "must not exceed 100",
    "must not exceed 1000",
    "must not exceed 86400",
    "must not exceed 100000",
)

_SOURCE_ID_REQUIRED_ERROR = (
    "source-id is required through "
    "--source-id or URLHAUS_SOURCE_ID"
)

_SOURCE_ID_INVALID_ERROR = (
    "source-id must be a valid UUID"
)

_GENERIC_FAILURE_MESSAGE = (
    "normalization execution failed"
)


def _parse_arguments(
    argv: Sequence[str] | None = None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Normalize pending URLhaus raw payloads "
            "into PostgreSQL."
        ),
    )

    parser.add_argument(
        "--source-id",
        required=False,
        help=(
            "UUID of the URLhaus source. "
            "Falls back to URLHAUS_SOURCE_ID."
        ),
    )

    return parser.parse_args(
        argv
    )


def _resolve_source_id(
    value: str | None,
) -> UUID:
    raw_value = (
        value
        if value is not None
        else os.environ.get(
            URLHAUS_SOURCE_ID_ENV
        )
    )

    if raw_value is None:
        raise ValueError(
            _SOURCE_ID_REQUIRED_ERROR
        )

    normalized_value = (
        raw_value.strip()
    )

    if not normalized_value:
        raise ValueError(
            _SOURCE_ID_REQUIRED_ERROR
        )

    try:
        return UUID(
            normalized_value
        )

    except ValueError as error:
        raise ValueError(
            _SOURCE_ID_INVALID_ERROR
        ) from error


def main(
    argv: Sequence[str] | None = None,
) -> int:
    """
    Exécute la normalisation URLhaus.

    Codes de sortie :

    - 0 : exécution réussie ;
    - 1 : configuration ou exécution invalide ;
    - 2 : argument argparse invalide.
    """

    try:
        configure_logging()

        arguments = _parse_arguments(
            argv
        )

        source_id = _resolve_source_id(
            arguments.source_id
        )

        job = (
            build_urlhaus_normalization_job(
                source_id=source_id,
            )
        )

        started_at = perf_counter()

        result = job.run()

        duration_seconds = (
            perf_counter()
            - started_at
        )

        logger.info(
            (
                "URLhaus normalization "
                "execution completed"
            ),
            extra={
                "source_id": str(
                    source_id
                ),
                "batches": result.batches,
                "claimed": result.claimed,
                "normalized": (
                    result.normalized
                ),
                "already_normalized": (
                    result.already_normalized
                ),
                "failed": result.failed,
                "requeued": result.requeued,
                "stale_failed": (
                    result.stale_failed
                ),
                "duration_seconds": round(
                    duration_seconds,
                    3,
                ),
            },
        )

        print(
            "URLhaus normalization completed: "
            f"batches={result.batches}, "
            f"claimed={result.claimed}, "
            f"normalized={result.normalized}, "
            "already_normalized="
            f"{result.already_normalized}, "
            f"failed={result.failed}, "
            f"requeued={result.requeued}, "
            f"stale_failed={result.stale_failed}, "
            "duration_seconds="
            f"{duration_seconds:.3f}"
        )

        return 0

    except Exception as error:
        error_summary = (
            _build_safe_error_summary(
                error
            )
        )

        logger.error(
            (
                "URLhaus normalization "
                "execution failed"
            ),
            extra={
                "error_type": (
                    type(error).__name__
                ),
                "error_summary": (
                    error_summary
                ),
            },
        )

        print(
            "URLhaus normalization failed: "
            f"{error_summary}",
            file=sys.stderr,
        )

        return 1


def _build_safe_error_summary(
    error: Exception,
) -> str:
    error_type = (
        type(error).__name__
    )

    error_message = str(
        error
    ).strip()

    if (
        isinstance(
            error,
            ValueError,
        )
        and error_message
        in {
            _SOURCE_ID_REQUIRED_ERROR,
            _SOURCE_ID_INVALID_ERROR,
        }
    ):
        return (
            f"{error_type}: "
            f"{error_message}"
        )

    if (
        isinstance(
            error,
            RuntimeError,
        )
        and _is_safe_configuration_error(
            error_message
        )
    ):
        return (
            f"{error_type}: "
            f"{error_message}"
        )

    return (
        f"{error_type}: "
        f"{_GENERIC_FAILURE_MESSAGE}"
    )


def _is_safe_configuration_error(
    message: str,
) -> bool:
    return any(
        message
        == f"{variable_name} {suffix}"
        for variable_name
        in _SAFE_CONFIGURATION_VARIABLES
        for suffix
        in _SAFE_CONFIGURATION_SUFFIXES
    )


if __name__ == "__main__":
    raise SystemExit(
        main()
    )