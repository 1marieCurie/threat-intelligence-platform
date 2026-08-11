from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv


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
from collections.abc import Sequence
from time import perf_counter


if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(
        0,
        str(PROJECT_ROOT),
    )


from application.services.canonical_url_normalizer import (
    CanonicalURLNormalizer,
)
from application.services.http_archive_page_persistence_service import (
    HTTPArchivePagePersistenceService,
)
from infrastructure.adapters.inbound.benign_candidate_csv_source import (
    BenignCandidateCSVSource,
)
from infrastructure.persistence.sqlalchemy.engine import (
    create_ingestion_engine,
)
from infrastructure.persistence.sqlalchemy.http_archive_page import (
    SqlAlchemyHTTPArchivePageStore,
)
from infrastructure.persistence.sqlalchemy.session import (
    create_session_factory,
)

DEFAULT_SOURCE_SNAPSHOT = (
    "http-archive-"
    "2026-07-01-"
    "mobile-secondary"
)


def _parse_arguments(
    argv: Sequence[str] | None = None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Persist normalized HTTP Archive "
            "pages before ML projection."
        )
    )

    parser.add_argument(
        "--candidates-file",
        type=Path,
        required=True,
    )

    parser.add_argument(
        "--source-snapshot",
        default=DEFAULT_SOURCE_SNAPSHOT,
    )

    parser.add_argument(
        "--batch-size",
        type=int,
        default=1_000,
    )

    return parser.parse_args(
        argv
    )


def main(
    argv: Sequence[str] | None = None,
) -> int:
    arguments = (
        _parse_arguments(
            argv
        )
    )

    engine = None

    try:
        if (
            not arguments.candidates_file.exists()
            or not arguments.candidates_file.is_file()
        ):
            raise ValueError(
                "candidate file does not exist"
            )

        started_at = (
            perf_counter()
        )

        engine = (
            create_ingestion_engine()
        )

        session_factory = (
            create_session_factory(
                engine
            )
        )

        store = (
            SqlAlchemyHTTPArchivePageStore(
                session_factory=(
                    session_factory
                )
            )
        )

        source = (
            BenignCandidateCSVSource(
                path=(
                    arguments.candidates_file
                )
            )
        )

        service = (
            HTTPArchivePagePersistenceService(
                store=store,
                normalizer=(
                    CanonicalURLNormalizer()
                ),
                expected_source_snapshot=(
                    arguments
                    .source_snapshot
                ),
                batch_size=(
                    arguments.batch_size
                ),
            )
        )

        result = service.run(
            source.iter_candidates()
        )

        duration_seconds = (
            perf_counter()
            - started_at
        )

        print(
            "HTTP Archive persistence completed: "
            f"candidates_read="
            f"{result.candidates_read}, "
            f"normalized="
            f"{result.normalized}, "
            f"normalization_rejected="
            f"{result.normalization_rejected}, "
            f"source_rejected="
            f"{result.source_rejected}, "
            f"submitted="
            f"{result.submitted}, "
            f"inserted="
            f"{result.inserted}, "
            f"already_existing="
            f"{result.already_existing}, "
            f"duration_seconds="
            f"{duration_seconds:.3f}"
        )

        return 0

    except Exception as error:
        # Ne jamais afficher str(error) :
        # une erreur peut contenir une URL.
        print(
            "HTTP Archive persistence failed: "
            f"{type(error).__name__}",
            file=sys.stderr,
        )

        return 1

    finally:
        if engine is not None:
            engine.dispose()


if __name__ == "__main__":
    raise SystemExit(
        main()
    )