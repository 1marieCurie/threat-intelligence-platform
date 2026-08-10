from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(
    __file__
).resolve().parents[2]

ENV_FILE = (
    PROJECT_ROOT
    / ".env"
)

load_dotenv(
    dotenv_path=ENV_FILE,
    override=False,
)


import argparse
import hashlib
import sys
from collections.abc import Sequence
from time import perf_counter

from application.models.ml_dataset import (
    MLDatasetSnapshotSpec,
)
from application.services.benign_dataset_selection_service import (
    BenignDatasetSelectionService,
)
from application.services.canonical_url_normalizer import (
    CanonicalURLNormalizer,
)
from application.services.ml_url_training_projector import (
    MLURLTrainingProjector,
)
from infrastructure.adapters.inbound.benign_candidate_csv_source import (
    BenignCandidateCSVSource,
)
from infrastructure.persistence.sqlalchemy.engine import (
    create_ingestion_engine,
)
from infrastructure.persistence.sqlalchemy.ml_dataset import (
    SqlAlchemyMLDatasetStore,
    SqlAlchemyMLThreatIdentityReader,
)
from infrastructure.persistence.sqlalchemy.session import (
    create_session_factory,
)


DEFAULT_TARGET_SIZE = 60_000
DEFAULT_MAX_PER_DOMAIN = 4

MAX_TARGET_SIZE = 100_000
MAX_PER_DOMAIN = 10

MAX_TRANCO_RANK = 100_000

DATASET_NAME = "benign_pool"

SELECTION_ALGORITHM_VERSION = (
    "1.0.0"
)


def _parse_arguments(
    argv: Sequence[str] | None = None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Build the privacy-safe benign "
            "URL ML dataset."
        ),
    )

    parser.add_argument(
        "--candidates-file",
        type=Path,
        required=True,
        help=(
            "Temporary local Tranco + CrUX "
            "candidate CSV."
        ),
    )

    parser.add_argument(
        "--dataset-version",
        required=True,
        help=(
            "Immutable logical dataset version."
        ),
    )

    parser.add_argument(
        "--source-snapshot",
        required=True,
        help=(
            "Expected source snapshot identifier."
        ),
    )

    parser.add_argument(
        "--target-size",
        type=int,
        default=DEFAULT_TARGET_SIZE,
        help=(
            "Target number of benign samples. "
            "Default: 60000."
        ),
    )

    parser.add_argument(
        "--max-per-domain",
        type=int,
        default=DEFAULT_MAX_PER_DOMAIN,
        help=(
            "Maximum samples per registered "
            "domain. Default: 4."
        ),
    )

    return parser.parse_args(
        argv
    )


def _validate_arguments(
    arguments: argparse.Namespace,
) -> None:
    if (
        isinstance(
            arguments.target_size,
            bool,
        )
        or not isinstance(
            arguments.target_size,
            int,
        )
        or not (
            1
            <= arguments.target_size
            <= MAX_TARGET_SIZE
        )
    ):
        raise ValueError(
            "target_size must be between "
            f"1 and {MAX_TARGET_SIZE}"
        )

    if (
        isinstance(
            arguments.max_per_domain,
            bool,
        )
        or not isinstance(
            arguments.max_per_domain,
            int,
        )
        or not (
            1
            <= arguments.max_per_domain
            <= MAX_PER_DOMAIN
        )
    ):
        raise ValueError(
            "max_per_domain must be between "
            f"1 and {MAX_PER_DOMAIN}"
        )

    dataset_version = (
        arguments.dataset_version.strip()
    )

    if not dataset_version:
        raise ValueError(
            "dataset_version must not be empty"
        )

    source_snapshot = (
        arguments.source_snapshot.strip()
    )

    if not source_snapshot:
        raise ValueError(
            "source_snapshot must not be empty"
        )

    candidates_file = (
        arguments.candidates_file
    )

    if (
        not candidates_file.exists()
        or not candidates_file.is_file()
    ):
        raise ValueError(
            "candidate file does not exist"
        )


def _compute_sha256(
    path: Path,
) -> str:
    digest = hashlib.sha256()

    try:
        with path.open(
            "rb"
        ) as handle:
            while True:
                chunk = handle.read(
                    1024 * 1024
                )

                if not chunk:
                    break

                digest.update(
                    chunk
                )

    except OSError:
        raise RuntimeError(
            "Unable to hash candidate file"
        ) from None

    return digest.hexdigest()


def main(
    argv: Sequence[str] | None = None,
) -> int:
    arguments = _parse_arguments(
        argv
    )

    engine = None

    try:
        _validate_arguments(
            arguments
        )

        started_at = perf_counter()

        candidate_file_hash = (
            _compute_sha256(
                arguments.candidates_file
            )
        )

        dataset_version = (
            arguments.dataset_version.strip()
        )

        source_snapshot = (
            arguments.source_snapshot.strip()
        )

        projector = (
            MLURLTrainingProjector()
        )

        snapshot_spec = (
            MLDatasetSnapshotSpec(
                name=DATASET_NAME,
                version=dataset_version,
                projection_version=(
                    projector.VERSION
                ),
                class_targets={
                    "benign": (
                        arguments.target_size
                    ),
                },
                label_mapping={
                    "benign": 0,
                    "phishing": 1,
                    "malware_distribution": 2,
                },
                selection_config={
                    "selection_algorithm_version": (
                        SELECTION_ALGORITHM_VERSION
                    ),
                    "max_per_registered_domain": (
                        arguments.max_per_domain
                    ),
                    "max_tranco_rank": (
                        MAX_TRANCO_RANK
                    ),
                    "requires_tranco": True,
                    "requires_crux": True,
                    "exclude_canonical_threats": True,
                    "network_access": False,
                },
                source_manifest={
                    "source_snapshot": (
                        source_snapshot
                    ),
                    "candidate_file_sha256": (
                        candidate_file_hash
                    ),
                },
            )
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
            SqlAlchemyMLDatasetStore(
                session_factory=(
                    session_factory
                )
            )
        )

        threat_identity_reader = (
            SqlAlchemyMLThreatIdentityReader(
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
            BenignDatasetSelectionService(
                store=store,
                threat_identity_reader=(
                    threat_identity_reader
                ),
                normalizer=(
                    CanonicalURLNormalizer()
                ),
                projector=projector,
                snapshot_spec=(
                    snapshot_spec
                ),
                expected_source_snapshot=(
                    source_snapshot
                ),
                target_size=(
                    arguments.target_size
                ),
                max_per_domain=(
                    arguments.max_per_domain
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
            (
                "Benign ML dataset build completed: "
                f"dataset_id={result.dataset_id}, "
                f"candidates_read="
                f"{result.candidates_read}, "
                f"normalized="
                f"{result.candidates_normalized}, "
                f"normalization_rejected="
                f"{result.normalization_rejected}, "
                f"source_rejected="
                f"{result.source_rejected}, "
                f"duplicate_rejected="
                f"{result.duplicate_rejected}, "
                f"threat_rejected="
                f"{result.threat_rejected}, "
                f"domain_quota_rejected="
                f"{result.domain_quota_rejected}, "
                f"starting_members="
                f"{result.starting_members}, "
                f"inserted_members="
                f"{result.inserted_members}, "
                f"final_members="
                f"{result.final_members}, "
                f"target="
                f"{result.target_size}, "
                f"target_reached="
                f"{result.target_reached}, "
                f"duration_seconds="
                f"{duration_seconds:.3f}"
            )
        )

        return (
            0
            if result.target_reached
            else 2
        )

    except Exception as error:
        # Important :
        # pas de str(error), car une exception provider,
        # CSV ou SQL pourrait contenir un chemin ou
        # potentiellement une donnée brute.
        print(
            (
                "Benign ML dataset build failed: "
                f"{type(error).__name__}"
            ),
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