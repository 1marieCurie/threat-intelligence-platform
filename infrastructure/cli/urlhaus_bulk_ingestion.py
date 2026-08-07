from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy.engine import Engine


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)

load_dotenv(
    dotenv_path=PROJECT_ROOT / ".env",
    override=False,
)


import argparse
import sys
from typing import Any, cast
from collections.abc import Sequence
from time import perf_counter

from infrastructure.bootstrap.urlhaus_bulk_ingestion import (
    build_urlhaus_bulk_ingestion,
)


def _parse_arguments(
    argv: Sequence[str] | None = None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Bootstrap URLhaus from the "
            "official active + 90 day dump."
        )
    )

    parser.add_argument(
        "--batch-size",
        type=int,
        default=500,
    )

    return parser.parse_args(
        argv
    )


def main(
    argv: Sequence[str] | None = None,
) -> int:
    arguments = _parse_arguments(
        argv
    )

    engine: Engine | None = None

    try:
        (
            connector,
            service,
            source_id,
            engine,
        ) = build_urlhaus_bulk_ingestion(
            batch_size=(
                arguments.batch_size
            )
        )

        started_at = perf_counter()

        result = service.ingest(
            source_id=source_id,
            records=(
                connector.iter_records()
            ),
        )

        duration = (
            perf_counter()
            - started_at
        )

        print(
            "URLhaus bulk ingestion completed: "
            f"run_id={result.run_id}, "
            "records_received="
            f"{result.records_received}, "
            "records_inserted="
            f"{result.records_inserted}, "
            "records_existing="
            f"{result.records_existing}, "
            "batches="
            f"{result.batches_processed}, "
            f"duration_seconds={duration:.3f}"
        )

        return 0

    except Exception as error:
        # Ne jamais afficher str(error) :
        # une exception réseau pourrait contenir
        # l'URL authentifiée ou un IOC.
        print(
            "URLhaus bulk ingestion failed: "
            f"{type(error).__name__}",
            file=sys.stderr,
        )

        return 1

    finally:
        if engine is not None and hasattr(engine, 'close'):
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(
        main()
    )