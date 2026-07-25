import argparse
import sys
from uuid import UUID

from dotenv import find_dotenv, load_dotenv

from infrastructure.bootstrap.github_advisory_ingestion import (
    build_github_advisory_ingestion_job,
)


DEFAULT_MAX_PAGES = 1
MAX_ALLOWED_PAGES = 100


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Ingest GitHub Security Advisories "
            "into PostgreSQL."
        ),
    )

    parser.add_argument(
        "--source-id",
        required=True,
        help="UUID of the GitHub advisory source.",
    )

    parser.add_argument(
        "--max-pages",
        type=int,
        default=DEFAULT_MAX_PAGES,
        help=(
            "Maximum number of GitHub pages to process "
            f"during one execution. Default: "
            f"{DEFAULT_MAX_PAGES}. Maximum: "
            f"{MAX_ALLOWED_PAGES}."
        ),
    )

    return parser.parse_args()


def _parse_source_id(value: str) -> UUID:
    try:
        return UUID(value)
    except (TypeError, ValueError) as error:
        raise ValueError(
            "source-id must be a valid UUID"
        ) from error


def _validate_max_pages(value: int) -> int:
    if isinstance(value, bool) or not isinstance(
        value,
        int,
    ):
        raise TypeError(
            "max-pages must be an integer"
        )

    if value < 1:
        raise ValueError(
            "max-pages must be greater than or equal to 1"
        )

    if value > MAX_ALLOWED_PAGES:
        raise ValueError(
            "max-pages must be less than or equal to "
            f"{MAX_ALLOWED_PAGES}"
        )

    return value


def main() -> int:
    load_dotenv(
        dotenv_path=find_dotenv(usecwd=True),
        override=False,
    )

    arguments = _parse_arguments()

    try:
        source_id = _parse_source_id(
            arguments.source_id
        )
        max_pages = _validate_max_pages(
            arguments.max_pages
        )

        job = build_github_advisory_ingestion_job(
            source_id=source_id,
        )

        total_received = 0
        total_persisted = 0
        total_skipped = 0
        pages_processed = 0
        pagination_complete = False

        for page_number in range(
            1,
            max_pages + 1,
        ):
            result = job.run()

            pages_processed = page_number
            total_received += result.records_received
            total_persisted += result.records_persisted
            total_skipped += result.records_skipped
            pagination_complete = (
                result.pagination_complete
            )

            if pagination_complete:
                break

        print(
            "GitHub advisory ingestion execution completed: "
            f"pages={pages_processed}, "
            f"received={total_received}, "
            f"persisted={total_persisted}, "
            f"skipped={total_skipped}, "
            f"pagination_complete={pagination_complete}"
        )

        return 0

    except Exception as error:
        print(
            f"GitHub advisory ingestion failed: {error}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

