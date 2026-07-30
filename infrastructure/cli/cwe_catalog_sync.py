from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Sequence
from time import perf_counter

from dotenv import find_dotenv, load_dotenv


load_dotenv(
    dotenv_path=find_dotenv(
        usecwd=True
    ),
    override=False,
)


from application.security.sensitive_data_redactor import (
    redact_sensitive_data,
)
from infrastructure.bootstrap.cwe_catalog_sync import (
    build_cwe_catalog_sync_job,
)
from infrastructure.logging.configuration import (
    configure_logging,
)


logger = logging.getLogger(__name__)


def _parse_arguments(
    argv: Sequence[str] | None = None,
) -> argparse.Namespace:
    """
    Analyse les arguments de la commande CWE.

    Aucun argument métier n'est nécessaire actuellement :
    la configuration est fournie par les variables d'environnement.
    """

    parser = argparse.ArgumentParser(
        description=(
            "Synchronize referenced CWE weaknesses "
            "from MITRE into PostgreSQL."
        ),
    )

    return parser.parse_args(
        argv
    )


def main(
    argv: Sequence[str] | None = None,
) -> int:
    """
    Exécute la synchronisation du catalogue CWE.

    Codes de sortie :

    - 0 : synchronisation réussie ;
    - 1 : erreur de configuration, réseau,
          mapping ou persistance ;
    - 2 : arguments CLI invalides gérés par argparse.
    """

    try:
        configure_logging()

        _parse_arguments(
            argv
        )

        job = (
            build_cwe_catalog_sync_job()
        )

        started_at = perf_counter()

        result = job.run()

        duration_seconds = (
            perf_counter()
            - started_at
        )

        missing_ids_count = len(
            result.missing_ids
        )

        logger.info(
            (
                "CWE catalog synchronization "
                "execution completed"
            ),
            extra={
                "catalog_version": (
                    result.catalog_version
                ),
                "catalog_date": (
                    result.catalog_date
                ),
                "requested_ids": (
                    result.requested_ids
                ),
                "fetched_weaknesses": (
                    result.fetched_weaknesses
                ),
                "persisted_weaknesses": (
                    result.persisted_weaknesses
                ),
                 "up_to_date_weaknesses": (
                    result.up_to_date_weaknesses
                ),
                "batches": result.batches,
                "missing_ids_count": (
                    missing_ids_count
                ),
                "duration_seconds": round(
                    duration_seconds,
                    3,
                ),
            },
        )

        print(
            (
                "CWE catalog synchronization "
                "completed: "
            )
            + (
                "catalog_version="
                f"{result.catalog_version}, "
            )
            + (
                "catalog_date="
                f"{result.catalog_date}, "
            )
            + (
                "requested_ids="
                f"{result.requested_ids}, "
            )
            + (
                "fetched_weaknesses="
                f"{result.fetched_weaknesses}, "
            )
            + (
                "persisted_weaknesses="
                f"{result.persisted_weaknesses}, "
            )
            + (
                "up_to_date_weaknesses="
                f"{result.up_to_date_weaknesses}, "
            )
            + f"batches={result.batches}, "
            + (
                "missing_ids_count="
                f"{missing_ids_count}, "
            )
            + (
                "duration_seconds="
                f"{duration_seconds:.3f}"
            )
        )

        return 0

    except Exception as error:
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

        logger.error(
            (
                "CWE catalog synchronization "
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
                "CWE catalog synchronization "
                "failed: "
                f"{sanitized_summary}"
            ),
            file=sys.stderr,
        )

        return 1


if __name__ == "__main__":
    raise SystemExit(
        main()
    )