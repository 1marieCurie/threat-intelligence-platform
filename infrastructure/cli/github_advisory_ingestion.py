import argparse
import sys
from uuid import UUID
import logging
from time import perf_counter
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

from infrastructure.bootstrap.github_advisory_ingestion import (
    build_github_advisory_ingestion_job,
)
from application.security.sensitive_data_redactor import (
    redact_sensitive_data,
)
from infrastructure.logging.configuration import (
    configure_logging,
)

logger = logging.getLogger(__name__)


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
    
    
    configure_logging()

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

        logger.info(
            "GitHub advisory ingestion cycle started",
            extra={
                "source_id": str(source_id),
                "max_pages": max_pages,
            },
        )

        started_at = perf_counter()

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

        duration_seconds = (
            perf_counter()
            - started_at
        )

        stop_reason = (
            "pagination_complete"
            if pagination_complete
            else "max_pages_reached"
        )

        log_method = (
            logger.info
            if pagination_complete
            else logger.warning
        )

        log_method(
            "GitHub advisory ingestion cycle completed",
            extra={
                "source_id": str(source_id),
                "pages_processed": pages_processed,
                "max_pages": max_pages,
                "records_received": total_received,
                "records_persisted": total_persisted,
                "records_skipped": total_skipped,
                "pagination_complete": (
                    pagination_complete
                ),
                "stop_reason": stop_reason,
                "duration_seconds": round(
                    duration_seconds,
                    3,
                ),
            },
        )

        print(
            "GitHub advisory ingestion execution completed: "
            f"pages={pages_processed}, "
            f"received={total_received}, "
            f"persisted={total_persisted}, "
            f"skipped={total_skipped}, "
            f"pagination_complete={pagination_complete}, "
            f"stop_reason={stop_reason}, "
            f"duration_seconds={duration_seconds:.3f}"
        )

        return 0



    except Exception as error:
        sanitized_error = redact_sensitive_data(
            str(error),
            max_length=500,
        )
        
        logger.error(
            "GitHub advisory ingestion cycle failed",
            extra={
                "error_type": (
                    type(error).__name__
                ),
                "error_message": sanitized_error,
            },
        )

        print(
            "GitHub advisory ingestion failed: "
            f"{sanitized_error}",
            file=sys.stderr,
        )

        return 1


if __name__ == "__main__":
    raise SystemExit(main())

