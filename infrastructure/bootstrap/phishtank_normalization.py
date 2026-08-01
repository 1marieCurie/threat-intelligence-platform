from __future__ import annotations

import os
from datetime import timedelta
from pathlib import Path
from uuid import UUID

from dotenv import load_dotenv

from application.services.phishtank_normalization_service import (
    PhishTankNormalizationService,
)
from application.services.phishtank_normalizer import (
    PhishTankNormalizer,
)
from infrastructure.adapters.inbound.phishtank_normalization_job import (
    PhishTankNormalizationJob,
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


PHISHTANK_SOURCE_CODE = "PHISHTANK"

PHISHTANK_NORMALIZATION_BATCH_SIZE_ENV = (
    "PHISHTANK_NORMALIZATION_BATCH_SIZE"
)

PHISHTANK_NORMALIZATION_LEASE_TIMEOUT_SECONDS_ENV = (
    "PHISHTANK_NORMALIZATION_"
    "LEASE_TIMEOUT_SECONDS"
)

PHISHTANK_NORMALIZATION_MAX_ATTEMPTS_ENV = (
    "PHISHTANK_NORMALIZATION_MAX_ATTEMPTS"
)

DEFAULT_BATCH_SIZE = 100
DEFAULT_LEASE_TIMEOUT_SECONDS = 900
DEFAULT_MAX_ATTEMPTS = 3


def build_phishtank_normalization_job(
    *,
    source_id: UUID,
) -> PhishTankNormalizationJob:
    """
    Assemble le pipeline de normalisation PhishTank.

    PostgreSQL
    -> session factory
    -> Unit of Work
    -> normalizer
    -> service transactionnel
    -> job
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
                PHISHTANK_NORMALIZATION_BATCH_SIZE_ENV
            ),
            default=DEFAULT_BATCH_SIZE,
        )
    )

    lease_timeout_seconds = (
        _read_positive_integer(
            variable_name=(
                PHISHTANK_NORMALIZATION_LEASE_TIMEOUT_SECONDS_ENV
            ),
            default=(
                DEFAULT_LEASE_TIMEOUT_SECONDS
            ),
        )
    )

    max_attempts = (
        _read_positive_integer(
            variable_name=(
                PHISHTANK_NORMALIZATION_MAX_ATTEMPTS_ENV
            ),
            default=DEFAULT_MAX_ATTEMPTS,
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
        PhishTankNormalizer()
    )

    normalization_service = (
        PhishTankNormalizationService(
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

    return PhishTankNormalizationJob(
        normalization_service=(
            normalization_service
        ),
        source_id=source_id,
        source_code=(
            PHISHTANK_SOURCE_CODE
        ),
        batch_size=batch_size,
    )


def _read_positive_integer(
    *,
    variable_name: str,
    default: int,
) -> int:
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

    return parsed_value