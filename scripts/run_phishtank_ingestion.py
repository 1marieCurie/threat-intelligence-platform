from __future__ import annotations
from  pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)

ENV_FILE = PROJECT_ROOT / ".env"

load_dotenv(
    dotenv_path=ENV_FILE,
    override=False,
)

import argparse
import os
from collections.abc import Sequence
from uuid import UUID

from infrastructure.bootstrap.phishtank_ingestion import (
    DEFAULT_BATCH_SIZE,
    build_phishtank_ingestion_job,
)


DEFAULT_SAFE_LIMIT = 100
MAX_SAFE_LIMIT = 1_000


def _positive_integer(
    value: str,
) -> int:
    try:
        parsed_value = int(value)
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


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run the PhishTank raw ingestion pipeline."
        ),
    )

    parser.add_argument(
        "--source-id",
        type=_source_uuid,
        default=None,
        help=(
            "UUID of the PHISHTANK row in ops.source. "
            "Defaults to PHISHTANK_SOURCE_ID."
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
            "Maximum number of records. "
            f"Default: {DEFAULT_SAFE_LIMIT}."
        ),
    )

    ingestion_scope.add_argument(
        "--full",
        action="store_true",
        help=(
            "Process the complete snapshot. "
            "Use only after limited validation."
        ),
    )

    parser.add_argument(
        "--batch-size",
        type=_positive_integer,
        default=DEFAULT_BATCH_SIZE,
        help=(
            "PostgreSQL batch size. "
            f"Default: {DEFAULT_BATCH_SIZE}."
        ),
    )

    parser.add_argument(
        "--force-download",
        action="store_true",
        help=(
            "Force downloading a new snapshot."
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
        "PHISHTANK_SOURCE_ID"
    )

    if environment_value is None:
        parser.error(
            "source ID is required through "
            "--source-id or PHISHTANK_SOURCE_ID"
        )

    try:
        return _source_uuid(
            environment_value
        )
    except argparse.ArgumentTypeError as error:
        parser.error(
            str(error)
        )


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

    if parsed_arguments.full:
        limit = None
    else:
        limit = (
            parsed_arguments.limit
            if parsed_arguments.limit is not None
            else DEFAULT_SAFE_LIMIT
        )

        if limit > MAX_SAFE_LIMIT:
            parser.error(
                f"limited ingestion must not exceed "
                f"{MAX_SAFE_LIMIT} records; use --full "
                "only after validation"
            )

    job = build_phishtank_ingestion_job(
        source_id=source_id,
        limit=limit,
        force_download=(
            parsed_arguments.force_download
        ),
        batch_size=(
            parsed_arguments.batch_size
        ),
    )

    result = job.run()

    print(
        "PhishTank ingestion completed: "
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