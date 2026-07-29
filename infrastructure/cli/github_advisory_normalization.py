from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence
from time import perf_counter
from uuid import UUID

from dotenv import find_dotenv, load_dotenv

from application.security.sensitive_data_redactor import (
    redact_sensitive_data,
)
from infrastructure.bootstrap.github_advisory_normalization import (
    build_github_advisory_normalization_job,
)
from infrastructure.logging.configuration import (
    configure_logging,
)


logger = logging.getLogger(__name__)


def _parse_arguments(
    argv: Sequence[str] | None = None,
) -> argparse.Namespace:
    """
    Analyse les arguments de la commande GHAD.

    argv reste injectable pour permettre des tests
    unitaires sans modifier sys.argv.
    """

    parser = argparse.ArgumentParser(
        description=(
            "Normalize pending GitHub Advisory "
            "raw payloads into PostgreSQL."
        ),
    )

    parser.add_argument(
        "--source-id",
        required=True,
        help=(
            "UUID of the GitHub Advisory source."
        ),
    )

    return parser.parse_args(argv)


def _parse_source_id(
    value: str,
) -> UUID:
    """
    Convertit l'identifiant de source en UUID.
    """

    try:
        return UUID(value)

    except (TypeError, ValueError) as error:
        raise ValueError(
            "source-id must be a valid UUID"
        ) from error


def main(
    argv: Sequence[str] | None = None,
) -> int:
    """
    Exécute la normalisation GitHub Advisory.

    Codes de sortie :

    - 0 : exécution réussie ;
    - 1 : erreur de configuration, persistance
          ou traitement ;
    - 2 : arguments CLI invalides gérés par argparse.
    """

    try:
        load_dotenv(
            dotenv_path=find_dotenv(
                usecwd=True
            ),
            override=False,
        )

        configure_logging()

        arguments = _parse_arguments(
            argv
        )

        source_id = _parse_source_id(
            arguments.source_id
        )

        job = (
            build_github_advisory_normalization_job(
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
                "GitHub Advisory normalization "
                "execution completed"
            ),
            extra={
                "source_id": str(source_id),
                "batches": result.batches,
                "claimed": result.claimed,
                "normalized": result.normalized,
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
            (
                "GitHub Advisory normalization "
                "completed: "
            )
            + f"batches={result.batches}, "
            + f"claimed={result.claimed}, "
            + f"normalized={result.normalized}, "
            + (
                "already_normalized="
                f"{result.already_normalized}, "
            )
            + f"failed={result.failed}, "
            + f"requeued={result.requeued}, "
            + (
                "stale_failed="
                f"{result.stale_failed}, "
            )
            + (
                "duration_seconds="
                f"{duration_seconds:.3f}"
            )
        )

        return 0

    except Exception as error:
        error_type = type(error).__name__
        error_message = str(error).strip()

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

        logger.error(
            (
                "GitHub Advisory normalization "
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
                "GitHub Advisory "
                "normalization failed: "
                f"{sanitized_summary}"
            ),
            file=sys.stderr,
        )

        return 1


if __name__ == "__main__":
    raise SystemExit(
        main()
    )