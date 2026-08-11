from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from time import perf_counter
from typing import Iterable, Literal, cast

from dotenv import load_dotenv
from sqlalchemy.engine import Engine

PROJECT_ROOT = Path(__file__).resolve().parents[2]

load_dotenv(dotenv_path=PROJECT_ROOT / ".env", override=False)

from infrastructure.adapters.outbound.urlhaus.urlhaus_database_dump_connector import DEFAULT_DUMP_SCOPE
from infrastructure.bootstrap.urlhaus_bulk_ingestion import build_urlhaus_bulk_ingestion

URLhausDumpScope = Literal["active_only", "active_or_last_90_days"]

SUPPORTED_DUMP_SCOPES: tuple[URLhausDumpScope, ...] = (
    "active_only",
    "active_or_last_90_days",
)


def _parse_dump_scope(value: str) -> URLhausDumpScope:
    if value not in SUPPORTED_DUMP_SCOPES:
        raise argparse.ArgumentTypeError(
            "dump scope must be one of: "
            "active_only, "
            "active_or_last_90_days"
        )

    return cast(URLhausDumpScope, value)


def _parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Bootstrap URLhaus from the "
            "official database dump."
        )
    )

    parser.add_argument(
        "--batch-size",
        type=int,
        default=500,
    )

    parser.add_argument(
        "--dump-scope",
        type=_parse_dump_scope,
        choices=SUPPORTED_DUMP_SCOPES,
        default=cast(URLhausDumpScope, DEFAULT_DUMP_SCOPE),
        help=(
            "URLhaus dump scope. "
            "active_only downloads only "
            "currently active malware URLs; "
            "active_or_last_90_days keeps "
            "the default 90-day window."
        ),
    )

    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parse_arguments(argv)

    dump_scope = cast(URLhausDumpScope, arguments.dump_scope)

    engine: Engine | None = None

    try:
        connector, service, source_id, engine = build_urlhaus_bulk_ingestion(
            batch_size=arguments.batch_size,
            dump_scope=dump_scope,
        )

        started_at = perf_counter()

        result = service.ingest(
            source_id=source_id,
            records=connector.iter_records(),  # type: ignore[arg-type]
            dump_scope=dump_scope,
        )

        duration = perf_counter() - started_at

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
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())
