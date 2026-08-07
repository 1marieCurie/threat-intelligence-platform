from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(
    __file__
).resolve().parents[2]

ENV_FILE = PROJECT_ROOT / ".env"

load_dotenv(
    dotenv_path=ENV_FILE,
    override=False,
)


import argparse
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from time import perf_counter

from sqlalchemy import select
from sqlalchemy.orm import (
    Session,
    sessionmaker,
)

from infrastructure.bootstrap.epss_canonical_correlation import (
    build_epss_canonical_correlation_job,
)
from infrastructure.bootstrap.epss_synchronization import (
    build_epss_synchronization_job,
)
from infrastructure.persistence.models.canonical import (
    CanonicalVulnerabilityIdentifierModel,
    CanonicalVulnerabilityModel,
)
from infrastructure.persistence.sqlalchemy.engine import (
    create_ingestion_engine,
)
from infrastructure.persistence.sqlalchemy.session import (
    create_session_factory,
)


DEFAULT_BATCH_SIZE = 500
MAX_BATCH_SIZE = 1_000

DEFAULT_MAX_BATCHES = 10_000


@dataclass(
    slots=True,
)
class EPSSBackfillCounters:
    batches_processed: int = 0

    canonical_cves_read: int = 0

    scores_fetched: int = 0
    scores_submitted: int = 0
    scores_missing: int = 0


def _parse_arguments(
    argv: Sequence[str] | None = None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Backfill FIRST EPSS scores for all "
            "canonical CVE vulnerabilities."
        ),
    )

    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
        help=(
            "Canonical CVE batch size. "
            "Default: 500."
        ),
    )

    parser.add_argument(
        "--max-batches",
        type=int,
        default=DEFAULT_MAX_BATCHES,
        help=(
            "Maximum number of canonical CVE "
            "batches to process."
        ),
    )

    parser.add_argument(
        "--skip-canonical",
        action="store_true",
        help=(
            "Synchronize normalized EPSS scores "
            "without running canonical enrichment."
        ),
    )

    return parser.parse_args(
        argv
    )


def _validate_batch_size(
    value: int,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
    ):
        raise TypeError(
            "batch_size must be an integer"
        )

    if not (
        1
        <= value
        <= MAX_BATCH_SIZE
    ):
        raise ValueError(
            "batch_size must be between "
            f"1 and {MAX_BATCH_SIZE}"
        )

    return value


def _validate_max_batches(
    value: int,
) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
    ):
        raise TypeError(
            "max_batches must be an integer"
        )

    if value < 1:
        raise ValueError(
            "max_batches must be "
            "greater than zero"
        )

    return value


def _read_canonical_cve_batch(
    *,
    session_factory: sessionmaker[Session],
    after_cve_id: str | None,
    limit: int,
) -> tuple[str, ...]:
    """
    Lit les CVE canoniques avec pagination keyset.

    Aucun OFFSET n'est utilisé afin de conserver
    des performances stables quand le volume augmente.
    """

    statement = (
        select(
            CanonicalVulnerabilityIdentifierModel.value
        )
        .join(
            CanonicalVulnerabilityModel,
            (
                CanonicalVulnerabilityModel.id
                == (
                    CanonicalVulnerabilityIdentifierModel
                    .vulnerability_id
                )
            ),
        )
        .where(
            (
                CanonicalVulnerabilityIdentifierModel
                .namespace
                == "CVE"
            ),
            (
                CanonicalVulnerabilityModel.status
                != "merged"
            ),
        )
    )

    if after_cve_id is not None:
        statement = statement.where(
            (
                CanonicalVulnerabilityIdentifierModel
                .value
            )
            > after_cve_id
        )

    statement = (
        statement
        .order_by(
            (
                CanonicalVulnerabilityIdentifierModel
                .value
                .asc()
            )
        )
        .limit(limit)
    )

    session = session_factory()

    try:
        rows = (
            session.execute(
                statement
            )
            .scalars()
            .all()
        )

        return tuple(rows)

    finally:
        session.close()


def _run_normalized_backfill(
    *,
    session_factory: sessionmaker[Session],
    batch_size: int,
    max_batches: int,
) -> EPSSBackfillCounters:
    synchronization_job = (
        build_epss_synchronization_job()
    )

    counters = EPSSBackfillCounters()

    cursor: str | None = None

    for _ in range(max_batches):
        cve_ids = (
            _read_canonical_cve_batch(
                session_factory=(
                    session_factory
                ),
                after_cve_id=cursor,
                limit=batch_size,
            )
        )

        if not cve_ids:
            break

        result = synchronization_job.run(
            cve_ids
        )

        counters.batches_processed += 1

        counters.canonical_cves_read += (
            len(cve_ids)
        )

        counters.scores_fetched += (
            result.fetched_scores
        )

        counters.scores_submitted += (
            result.submitted_scores
        )

        counters.scores_missing += (
            len(result.missing_cves)
        )

        print(
            (
                "EPSS batch completed: "
                f"batch={counters.batches_processed}, "
                f"requested={len(cve_ids)}, "
                f"fetched={result.fetched_scores}, "
                f"submitted={result.submitted_scores}, "
                f"missing={len(result.missing_cves)}"
            )
        )

        next_cursor = cve_ids[-1]

        if next_cursor == cursor:
            raise RuntimeError(
                "Canonical CVE cursor "
                "did not progress"
            )

        cursor = next_cursor

        if len(cve_ids) < batch_size:
            break

    return counters


def main(
    argv: Sequence[str] | None = None,
) -> int:
    arguments = _parse_arguments(
        argv
    )

    try:
        batch_size = _validate_batch_size(
            arguments.batch_size
        )

        max_batches = (
            _validate_max_batches(
                arguments.max_batches
            )
        )

        started_at = perf_counter()

        engine = create_ingestion_engine()

        session_factory = (
            create_session_factory(
                engine
            )
        )

        try:
            counters = (
                _run_normalized_backfill(
                    session_factory=(
                        session_factory
                    ),
                    batch_size=batch_size,
                    max_batches=max_batches,
                )
            )

        finally:
            engine.dispose()

        print(
            (
                "EPSS normalized backfill completed: "
                f"batches="
                f"{counters.batches_processed}, "
                f"canonical_cves="
                f"{counters.canonical_cves_read}, "
                f"fetched="
                f"{counters.scores_fetched}, "
                f"submitted="
                f"{counters.scores_submitted}, "
                f"missing="
                f"{counters.scores_missing}"
            )
        )

        if not arguments.skip_canonical:
            canonical_job = (
                build_epss_canonical_correlation_job()
            )

            canonical_result = (
                canonical_job.run()
            )

            print(
                (
                    "EPSS canonical enrichment "
                    "completed: "
                    f"batches="
                    f"{canonical_result.batches_processed}, "
                    f"records_read="
                    f"{canonical_result.records_read}, "
                    f"created="
                    f"{canonical_result.canonical_created}, "
                    f"updated="
                    f"{canonical_result.canonical_updated}, "
                    f"canonical_persisted="
                    f"{canonical_result.canonical_persisted}, "
                    f"epss_persisted="
                    f"{canonical_result.epss_persisted}"
                )
            )

        duration_seconds = (
            perf_counter()
            - started_at
        )

        print(
            (
                "EPSS backfill finished: "
                f"duration_seconds="
                f"{duration_seconds:.3f}"
            )
        )

        return 0

    except Exception as error:
        print(
            (
                "EPSS backfill failed: "
                f"{type(error).__name__}: "
                f"{error}"
            ),
            file=sys.stderr,
        )

        return 1


if __name__ == "__main__":
    raise SystemExit(
        main()
    )