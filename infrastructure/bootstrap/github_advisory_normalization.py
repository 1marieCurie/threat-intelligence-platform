from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path
from uuid import UUID

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = PROJECT_ROOT / ".env"

load_dotenv(
    dotenv_path=ENV_FILE,
    override=False,
)


from application.services.github_advisory_normalization_service import (
    GitHubAdvisoryNormalizationService,
)
from application.services.github_advisory_normalizer import (
    GitHubAdvisoryNormalizer,
)
from infrastructure.adapters.inbound.github_advisory_normalization_job import (
    GitHubAdvisoryNormalizationJob,
)
from infrastructure.persistence.sqlalchemy.engine import (
    create_ingestion_engine,
)
from infrastructure.persistence.sqlalchemy.session import (
    create_session_factory,
)
from infrastructure.persistence.sqlalchemy.unit_of_work import (
    SqlAlchemyUnitOfWork,
)


GITHUB_ADVISORY_SOURCE_CODE = "GITHUB_ADVISORY"

GITHUB_ADVISORY_NORMALIZATION_BATCH_SIZE_ENV = (
    "GITHUB_ADVISORY_NORMALIZATION_BATCH_SIZE"
)

GITHUB_ADVISORY_NORMALIZATION_MAX_BATCHES_ENV = (
    "GITHUB_ADVISORY_NORMALIZATION_MAX_BATCHES"
)

GITHUB_ADVISORY_NORMALIZATION_LEASE_TIMEOUT_SECONDS_ENV = (
    "GITHUB_ADVISORY_NORMALIZATION_"
    "LEASE_TIMEOUT_SECONDS"
)

GITHUB_ADVISORY_NORMALIZATION_MAX_ATTEMPTS_ENV = (
    "GITHUB_ADVISORY_NORMALIZATION_MAX_ATTEMPTS"
)

DEFAULT_BATCH_SIZE = 100
DEFAULT_MAX_BATCHES = 10_000
DEFAULT_LEASE_TIMEOUT_SECONDS = 900
DEFAULT_MAX_ATTEMPTS = 3


def build_github_advisory_normalization_job(
    *,
    source_id: UUID,
) -> GitHubAdvisoryNormalizationJob:
    """
    Assemble le pipeline de normalisation GitHub Advisory.

    Composition :

    PostgreSQL ingestion engine
    -> session factory
    -> Unit of Work
    -> GHAD normalizer
    -> normalization service
    -> bounded normalization job
    """

    if not isinstance(source_id, UUID):
        raise TypeError(
            "source_id must be a UUID"
        )

    # Toute la configuration est validée avant
    # l'ouverture d'une connexion PostgreSQL.
    batch_size = _read_positive_integer(
        variable_name=(
            GITHUB_ADVISORY_NORMALIZATION_BATCH_SIZE_ENV
        ),
        default=DEFAULT_BATCH_SIZE,
    )

    max_batches = _read_positive_integer(
        variable_name=(
            GITHUB_ADVISORY_NORMALIZATION_MAX_BATCHES_ENV
        ),
        default=DEFAULT_MAX_BATCHES,
    )

    lease_timeout_seconds = (
        _read_positive_integer(
            variable_name=(
                GITHUB_ADVISORY_NORMALIZATION_LEASE_TIMEOUT_SECONDS_ENV
            ),
            default=(
                DEFAULT_LEASE_TIMEOUT_SECONDS
            ),
        )
    )

    max_attempts = _read_positive_integer(
        variable_name=(
            GITHUB_ADVISORY_NORMALIZATION_MAX_ATTEMPTS_ENV
        ),
        default=DEFAULT_MAX_ATTEMPTS,
    )

    engine = create_ingestion_engine()

    session_factory = create_session_factory(
        engine
    )

    unit_of_work = SqlAlchemyUnitOfWork(
        session_factory=session_factory,
    )

    normalizer = GitHubAdvisoryNormalizer()

    normalization_service = (
        GitHubAdvisoryNormalizationService(
            unit_of_work=unit_of_work,
            normalizer=normalizer,
            lease_timeout=timedelta(
                seconds=lease_timeout_seconds
            ),
            max_attempts=max_attempts,
        )
    )

    return GitHubAdvisoryNormalizationJob(
        normalization_service=(
            normalization_service
        ),
        source_id=source_id,
        source_code=(
            GITHUB_ADVISORY_SOURCE_CODE
        ),
        batch_size=batch_size,
        max_batches=max_batches,
    )


def _read_positive_integer(
    *,
    variable_name: str,
    default: int,
) -> int:
    """
    Lit une variable d'environnement entière positive.

    Une valeur présente mais invalide provoque un échec
    immédiat afin d'éviter une exécution mal bornée.
    """

    raw_value = os.environ.get(
        variable_name
    )

    if raw_value is None:
        return default

    normalized_value = raw_value.strip()

    if not normalized_value:
        raise RuntimeError(
            f"{variable_name} must not be empty"
        )

    try:
        parsed_value = int(
            normalized_value
        )

    except ValueError as error:
        raise RuntimeError(
            f"{variable_name} must be an integer"
        ) from error

    if parsed_value < 1:
        raise RuntimeError(
            f"{variable_name} must be "
            "greater than zero"
        )

    return parsed_value