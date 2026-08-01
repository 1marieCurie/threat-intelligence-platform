from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence
from pathlib import Path
from time import perf_counter
from uuid import UUID

from dotenv import load_dotenv

from infrastructure.bootstrap.phishtank_normalization import (
    PHISHTANK_NORMALIZATION_BATCH_SIZE_ENV,
    PHISHTANK_NORMALIZATION_LEASE_TIMEOUT_SECONDS_ENV,
    PHISHTANK_NORMALIZATION_MAX_ATTEMPTS_ENV,
    build_phishtank_normalization_job,
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


_SAFE_CONFIGURATION_VARIABLES = frozenset(
    {
        PHISHTANK_NORMALIZATION_BATCH_SIZE_ENV,
        PHISHTANK_NORMALIZATION_LEASE_TIMEOUT_SECONDS_ENV,
        PHISHTANK_NORMALIZATION_MAX_ATTEMPTS_ENV,
    }
)

_SAFE_CONFIGURATION_SUFFIXES = (
    "must not be empty",
    "must be an integer",
    "must be greater than zero",
)

_SOURCE_ID_ERROR = (
    "source-id must be a valid UUID"
)

_GENERIC_FAILURE_MESSAGE = (
    "normalization execution failed"
)


def _parse_arguments(
    argv: Sequence[str] | None = None,
) -> argparse.Namespace:
    """
    Analyse les arguments de la commande.

    argv reste injectable afin de faciliter les tests unitaires.
    """

    parser = argparse.ArgumentParser(
        description=(
            "Normalize pending PhishTank raw payloads "
            "into PostgreSQL."
        ),
    )

    parser.add_argument(
        "--source-id",
        required=True,
        help="UUID of the PhishTank source.",
    )

    return parser.parse_args(
        argv
    )


def _parse_source_id(
    value: str,
) -> UUID:
    """
    Convertit l'identifiant reçu par la CLI en UUID.
    """

    try:
        return UUID(
            value
        )

    except (
        TypeError,
        ValueError,
    ) as error:
        raise ValueError(
            _SOURCE_ID_ERROR
        ) from error


def main(
    argv: Sequence[str] | None = None,
) -> int:
    """
    Exécute le pipeline de normalisation PhishTank.

    Codes de sortie :

    - 0 : exécution réussie ;
    - 1 : erreur de configuration ou d'exécution ;
    - 2 : arguments CLI invalides gérés par argparse.
    """

    try:
        configure_logging()

        arguments = _parse_arguments(
            argv
        )

        source_id = _parse_source_id(
            arguments.source_id
        )

        job = (
            build_phishtank_normalization_job(
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
                "PhishTank normalization "
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
            "PhishTank normalization completed: "
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
                "PhishTank normalization "
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
            "PhishTank normalization failed: "
            f"{error_summary}",
            file=sys.stderr,
        )

        return 1


def _build_safe_error_summary(
    error: Exception,
) -> str:
    """
    Construit un diagnostic qui ne copie jamais une URL IOC,
    des paramètres SQL ou un secret dans les logs.
    """

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
        == _SOURCE_ID_ERROR
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
    """
    Autorise uniquement les erreurs de configuration connues.
    """

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