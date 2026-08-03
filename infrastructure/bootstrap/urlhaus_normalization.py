from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path
from uuid import UUID

from dotenv import load_dotenv

from application.services.urlhaus_normalization_service import (
    URLhausNormalizationService,
)
from application.services.urlhaus_normalizer import (
    URLhausNormalizer,
)
from infrastructure.adapters.inbound.urlhaus_normalization_job import (
    URLHAUS_NORMALIZATION_MAX_BATCH_SIZE,
    URLhausNormalizationJob,
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


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)

ENV_FILE = (
    PROJECT_ROOT
    / ".env"
)

load_dotenv(
    dotenv_path=ENV_FILE,
    override=False,
)


URLHAUS_SOURCE_CODE = "URLHAUS"


URLHAUS_NORMALIZATION_BATCH_SIZE_ENV = (
    "URLHAUS_NORMALIZATION_BATCH_SIZE"
)

URLHAUS_NORMALIZATION_LEASE_TIMEOUT_SECONDS_ENV = (
    "URLHAUS_NORMALIZATION_"
    "LEASE_TIMEOUT_SECONDS"
)

URLHAUS_NORMALIZATION_MAX_ATTEMPTS_ENV = (
    "URLHAUS_NORMALIZATION_MAX_ATTEMPTS"
)

URLHAUS_NORMALIZATION_MAX_BATCHES_ENV = (
    "URLHAUS_NORMALIZATION_MAX_BATCHES"
)


DEFAULT_BATCH_SIZE = 100
DEFAULT_LEASE_TIMEOUT_SECONDS = 900
DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_MAX_BATCHES = 10_000


MAX_LEASE_TIMEOUT_SECONDS = 86_400
MAX_ATTEMPTS = 100
MAX_BATCHES = 100_000


def build_urlhaus_normalization_job(
    *,
    source_id: UUID,
) -> URLhausNormalizationJob:
    """
    Assemble le pipeline de normalisation URLhaus.

    PostgreSQL
    -> session factory
    -> Unit of Work
    -> normaliseur pur
    -> service transactionnel
    -> job borné
    """

    if not isinstance(
        source_id,
        UUID,
    ):
        raise TypeError(
            "source_id must be a UUID"
        )

    batch_size = (
        _read_positive_integer(
            variable_name=(
                URLHAUS_NORMALIZATION_BATCH_SIZE_ENV
            ),
            default=DEFAULT_BATCH_SIZE,
            maximum=(
                URLHAUS_NORMALIZATION_MAX_BATCH_SIZE
            ),
        )
    )

    lease_timeout_seconds = (
        _read_positive_integer(
            variable_name=(
                URLHAUS_NORMALIZATION_LEASE_TIMEOUT_SECONDS_ENV
            ),
            default=(
                DEFAULT_LEASE_TIMEOUT_SECONDS
            ),
            maximum=(
                MAX_LEASE_TIMEOUT_SECONDS
            ),
        )
    )

    max_attempts = (
        _read_positive_integer(
            variable_name=(
                URLHAUS_NORMALIZATION_MAX_ATTEMPTS_ENV
            ),
            default=DEFAULT_MAX_ATTEMPTS,
            maximum=MAX_ATTEMPTS,
        )
    )

    max_batches = (
        _read_positive_integer(
            variable_name=(
                URLHAUS_NORMALIZATION_MAX_BATCHES_ENV
            ),
            default=DEFAULT_MAX_BATCHES,
            maximum=MAX_BATCHES,
        )
    )

    engine = create_ingestion_engine()

    session_factory = (
        create_session_factory(
            engine
        )
    )

    unit_of_work = (
        SqlAlchemyUnitOfWork(
            session_factory=(
                session_factory
            ),
        )
    )

    normalizer = (
        URLhausNormalizer()
    )

    normalization_service = (
        URLhausNormalizationService(
            unit_of_work=unit_of_work,
            normalizer=normalizer,
            lease_timeout=timedelta(
                seconds=(
                    lease_timeout_seconds
                ),
            ),
            max_attempts=max_attempts,
        )
    )

    return URLhausNormalizationJob(
        normalization_service=(
            normalization_service
        ),
        source_id=source_id,
        source_code=URLHAUS_SOURCE_CODE,
        batch_size=batch_size,
        max_batches=max_batches,
    )


def _read_positive_integer(
    *,
    variable_name: str,
    default: int,
    maximum: int,
) -> int:
    """
    Lit une configuration entière positive et bornée.

    La validation est réalisée avant l'ouverture de toute
    connexion PostgreSQL.
    """

    if (
        isinstance(
            default,
            bool,
        )
        or not isinstance(
            default,
            int,
        )
        or default < 1
    ):
        raise ValueError(
            "default must be a positive integer"
        )

    if (
        isinstance(
            maximum,
            bool,
        )
        or not isinstance(
            maximum,
            int,
        )
        or maximum < 1
    ):
        raise ValueError(
            "maximum must be a positive integer"
        )

    if default > maximum:
        raise ValueError(
            "default must not exceed maximum"
        )

    raw_value = os.environ.get(
        variable_name
    )

    if raw_value is None:
        return default

    normalized_value = (
        raw_value.strip()
    )

    if not normalized_value:
        raise RuntimeError(
            f"{variable_name} "
            "must not be empty"
        )

    try:
        parsed_value = int(
            normalized_value
        )

    except ValueError as error:
        raise RuntimeError(
            f"{variable_name} "
            "must be an integer"
        ) from error

    if parsed_value < 1:
        raise RuntimeError(
            f"{variable_name} "
            "must be greater than zero"
        )

    if parsed_value > maximum:
        raise RuntimeError(
            f"{variable_name} "
            f"must not exceed {maximum}"
        )

    return parsed_value