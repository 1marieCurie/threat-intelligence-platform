from __future__ import annotations

from dotenv import find_dotenv, load_dotenv

load_dotenv(
    dotenv_path=find_dotenv(usecwd=True),
    override=False,
)


import argparse
import os
import sys
from collections.abc import Sequence
from uuid import UUID

from infrastructure.bootstrap.urlhaus_ingestion import (
    DEFAULT_BATCH_SIZE,
    build_urlhaus_ingestion_job,
)


DEFAULT_SAFE_LIMIT = 100
MAX_RECENT_LIMIT = 1_000


def _positive_integer(
    value: str,
) -> int:
    try:
        parsed_value = int(
            value
        )

    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "value must be an integer"
        ) from error

    if parsed_value < 1:
        raise argparse.ArgumentTypeError(
            "value must be greater than zero"
        )

    return parsed_value


def _source_uuid(
    value: str,
) -> UUID:
    try:
        return UUID(
            value.strip()
        )

    except (
        AttributeError,
        ValueError,
    ) as error:
        raise argparse.ArgumentTypeError(
            "source ID must be a valid UUID"
        ) from error


def _build_parser(
) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run the URLhaus raw ingestion "
            "pipeline."
        ),
    )

    parser.add_argument(
        "--source-id",
        type=_source_uuid,
        default=None,
        help=(
            "UUID of the URLHAUS row in "
            "ops.source. Defaults to "
            "URLHAUS_SOURCE_ID."
        ),
    )

    ingestion_scope = (
        parser.add_mutually_exclusive_group()
    )

    ingestion_scope.add_argument(
        "--limit",
        type=_positive_integer,
        default=None,
        help=(
            "Maximum number of recent URL "
            "records. "
            f"Default: {DEFAULT_SAFE_LIMIT}."
        ),
    )

    ingestion_scope.add_argument(
        "--max-window",
        action="store_true",
        help=(
            "Request the provider's maximum "
            "recent URL window. This is not "
            "a complete historical snapshot."
        ),
    )

    parser.add_argument(
        "--batch-size",
        type=_positive_integer,
        default=DEFAULT_BATCH_SIZE,
        help=(
            "PostgreSQL persistence batch "
            "size. "
            f"Default: {DEFAULT_BATCH_SIZE}."
        ),
    )

    return parser


def _resolve_source_id(
    *,
    argument_source_id: UUID | None,
    parser: argparse.ArgumentParser,
) -> UUID:
    if argument_source_id is not None:
        return argument_source_id

    environment_value = os.getenv(
        "URLHAUS_SOURCE_ID"
    )

    if environment_value is None:
        parser.error(
            "source ID is required through "
            "--source-id or "
            "URLHAUS_SOURCE_ID"
        )

    try:
        return _source_uuid(
            environment_value
        )

    except argparse.ArgumentTypeError as error:
        parser.error(
            str(error)
        )


def _resolve_limit(
    *,
    argument_limit: int | None,
    max_window: bool,
    parser: argparse.ArgumentParser,
) -> int | None:
    if max_window:
        return None

    limit = (
        argument_limit
        if argument_limit is not None
        else DEFAULT_SAFE_LIMIT
    )

    if limit > MAX_RECENT_LIMIT:
        parser.error(
            "URLhaus recent ingestion must "
            f"not exceed {MAX_RECENT_LIMIT} "
            "records"
        )

    return limit


def main(
    arguments: Sequence[str] | None = None,
) -> int:
    parser = _build_parser()

    parsed_arguments = parser.parse_args(
        arguments
    )

    source_id = _resolve_source_id(
        argument_source_id=(
            parsed_arguments.source_id
        ),
        parser=parser,
    )

    limit = _resolve_limit(
        argument_limit=(
            parsed_arguments.limit
        ),
        max_window=(
            parsed_arguments.max_window
        ),
        parser=parser,
    )

    try:
        job = build_urlhaus_ingestion_job(
            source_id=source_id,
            limit=limit,
            batch_size=(
                parsed_arguments.batch_size
            ),
        )

        result = job.run()

    except Exception:
        # Do not expose provider responses, IOC URLs,
        # PostgreSQL parameters or authentication data.
        print(
            "URLhaus ingestion failed: "
            "unexpected error.",
            file=sys.stderr,
        )

        return 1

    print(
        "URLhaus ingestion completed: "
        f"run_id={result.run_id}, "
        f"received={result.records_received}, "
        f"persisted={result.records_persisted}, "
        f"skipped={result.records_skipped}, "
        f"status={result.status}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(
        main()
    )