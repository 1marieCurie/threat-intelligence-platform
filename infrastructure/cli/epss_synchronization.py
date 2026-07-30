from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = PROJECT_ROOT / ".env"

load_dotenv(
    dotenv_path=ENV_FILE,
    override=False,
)


import argparse
import logging
import re
import sys
from collections.abc import Sequence
from datetime import date
from time import perf_counter

from application.security.sensitive_data_redactor import (
    redact_sensitive_data,
)
from infrastructure.bootstrap.epss_synchronization import (
    build_epss_synchronization_job,
)
from infrastructure.logging.configuration import (
    configure_logging,
)


logger = logging.getLogger(__name__)

_CVE_IDENTIFIER_PATTERN = re.compile(
    r"\bCVE-[A-Z0-9._-]+\b",
    flags=re.IGNORECASE,
)

_CVE_REDACTED_VALUE = "[CVE_REDACTED]"


def _parse_score_date(
    raw_value: str,
) -> date:
    """
    Convertit une date ISO YYYY-MM-DD.

    argparse transforme ArgumentTypeError en code de sortie 2.
    """
    try:
        return date.fromisoformat(
            raw_value
        )

    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "score date must use YYYY-MM-DD"
        ) from error


def _parse_arguments(
    argv: Sequence[str] | None = None,
) -> argparse.Namespace:
    """
    Analyse les arguments de synchronisation EPSS.

    Les CVE sont acceptés comme arguments positionnels.
    Ils ne sont jamais journalisés ni affichés dans le résumé.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Synchronize FIRST EPSS scores "
            "into PostgreSQL."
        ),
    )

    parser.add_argument(
        "cve_ids",
        nargs="+",
        metavar="CVE",
        help=(
            "One or more CVE identifiers to synchronize."
        ),
    )

    parser.add_argument(
        "--score-date",
        type=_parse_score_date,
        default=None,
        help=(
            "Optional historical EPSS date "
            "using YYYY-MM-DD."
        ),
    )

    return parser.parse_args(
        argv
    )


def main(
    argv: Sequence[str] | None = None,
) -> int:
    """
    Exécute une synchronisation EPSS.

    Codes de sortie :

    - 0 : synchronisation réussie ;
    - 1 : erreur de configuration, réseau ou persistance ;
    - 2 : arguments CLI invalides gérés par argparse.
    """
    try:
        configure_logging()

        arguments = _parse_arguments(
            argv
        )

        job = (
            build_epss_synchronization_job()
        )

        started_at = perf_counter()

        result = job.run(
            arguments.cve_ids,
            score_date=arguments.score_date,
        )

        duration_seconds = (
            perf_counter()
            - started_at
        )

        missing_cves_count = len(
            result.missing_cves
        )

        requested_score_date = (
            result.requested_score_date.isoformat()
            if result.requested_score_date is not None
            else None
        )

        logger.info(
            (
                "EPSS synchronization "
                "execution completed"
            ),
            extra={
                "requested_cves": (
                    result.requested_cves
                ),
                "fetched_scores": (
                    result.fetched_scores
                ),
                "submitted_scores": (
                    result.submitted_scores
                ),
                "missing_cves_count": (
                    missing_cves_count
                ),
                "historical_sync": (
                    result.requested_score_date
                    is not None
                ),
                "requested_score_date": (
                    requested_score_date
                ),
                "duration_seconds": round(
                    duration_seconds,
                    3,
                ),
            },
        )

        print(
            (
                "EPSS synchronization completed: "
                f"requested_cves="
                f"{result.requested_cves}, "
                f"fetched_scores="
                f"{result.fetched_scores}, "
                f"submitted_scores="
                f"{result.submitted_scores}, "
                f"missing_cves_count="
                f"{missing_cves_count}, "
                f"requested_score_date="
                f"{requested_score_date}, "
                f"duration_seconds="
                f"{duration_seconds:.3f}"
            )
        )

        return 0

    except Exception as error:
        error_type = type(
            error
        ).__name__

        sanitized_summary = (
            _sanitize_error_summary(
                error
            )
        )

        logger.error(
            (
                "EPSS synchronization "
                "execution failed"
            ),
            extra={
                "error_type": error_type,
                "error_summary": (
                    sanitized_summary
                ),
            },
        )

        print(
            (
                "EPSS synchronization failed: "
                f"{sanitized_summary}"
            ),
            file=sys.stderr,
        )

        return 1


def _sanitize_error_summary(
    error: Exception,
) -> str:
    """
    Supprime secrets, credentials et identifiants CVE.
    """
    error_type = type(
        error
    ).__name__

    error_message = str(
        error
    ).strip()

    raw_summary = (
        f"{error_type}: {error_message}"
        if error_message
        else error_type
    )

    sanitized_summary = (
        redact_sensitive_data(
            raw_summary,
            max_length=500,
        )
    )

    return _CVE_IDENTIFIER_PATTERN.sub(
        _CVE_REDACTED_VALUE,
        sanitized_summary,
    )


if __name__ == "__main__":
    raise SystemExit(
        main()
    )