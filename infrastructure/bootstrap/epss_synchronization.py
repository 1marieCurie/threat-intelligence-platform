from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = PROJECT_ROOT / ".env"

load_dotenv(
    dotenv_path=ENV_FILE,
    override=False,
)


import os
from math import isfinite

from application.services.epss_synchronization_service import (
    EPSSSynchronizationService,
)
from infrastructure.adapters.inbound.epss_synchronization_job import (
    EPSSSynchronizationJob,
)
from infrastructure.adapters.outbound.epss_connector import (
    EPSSConnector,
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


EPSS_API_TIMEOUT_SECONDS_ENV = (
    "EPSS_API_TIMEOUT_SECONDS"
)

EPSS_SYNC_MAX_CVE_IDS_ENV = (
    "EPSS_SYNC_MAX_CVE_IDS"
)

DEFAULT_API_TIMEOUT_SECONDS = 10.0
DEFAULT_MAX_CVE_IDS = 50_000

MAX_API_TIMEOUT_SECONDS = 120.0
MAX_ALLOWED_CVE_IDS = 50_000


def build_epss_synchronization_job(
) -> EPSSSynchronizationJob:
    """
    Assemble le point d'entrée complet de synchronisation EPSS.

    Composition :

    EPSSSynchronizationJob
        -> EPSSSynchronizationService
        -> EPSSConnector
        -> SqlAlchemyUnitOfWork
        -> PostgreSQL
    """
    synchronization_service = (
        build_epss_synchronization_service()
    )

    return EPSSSynchronizationJob(
        synchronization_service=(
            synchronization_service
        ),
    )


def build_epss_synchronization_service(
) -> EPSSSynchronizationService:
    """
    Assemble le service de synchronisation EPSS.

    Toute la configuration est validée avant :

    - la création du moteur PostgreSQL ;
    - l'allocation du pool de connexions ;
    - la création de la session HTTP FIRST.
    """
    timeout_seconds = _read_positive_number(
        variable_name=(
            EPSS_API_TIMEOUT_SECONDS_ENV
        ),
        default=DEFAULT_API_TIMEOUT_SECONDS,
    )

    max_cve_ids = _read_positive_integer(
        variable_name=(
            EPSS_SYNC_MAX_CVE_IDS_ENV
        ),
        default=DEFAULT_MAX_CVE_IDS,
    )

    if (
        timeout_seconds
        > MAX_API_TIMEOUT_SECONDS
    ):
        raise RuntimeError(
            f"{EPSS_API_TIMEOUT_SECONDS_ENV} "
            "must not exceed "
            f"{MAX_API_TIMEOUT_SECONDS:g}"
        )

    if max_cve_ids > MAX_ALLOWED_CVE_IDS:
        raise RuntimeError(
            f"{EPSS_SYNC_MAX_CVE_IDS_ENV} "
            "must not exceed "
            f"{MAX_ALLOWED_CVE_IDS}"
        )

    engine = create_ingestion_engine()

    session_factory = create_session_factory(
        engine
    )

    unit_of_work = SqlAlchemyUnitOfWork(
        session_factory=session_factory,
    )

    provider = EPSSConnector(
        timeout=timeout_seconds,
    )

    return EPSSSynchronizationService(
        provider=provider,
        unit_of_work=unit_of_work,
        max_cve_ids=max_cve_ids,
    )


def _read_positive_integer(
    *,
    variable_name: str,
    default: int,
) -> int:
    """
    Lit une variable d'environnement entière positive.
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


def _read_positive_number(
    *,
    variable_name: str,
    default: float,
) -> float:
    """
    Lit une variable d'environnement numérique,
    finie et strictement positive.
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
        parsed_value = float(
            normalized_value
        )

    except ValueError as error:
        raise RuntimeError(
            f"{variable_name} must be a number"
        ) from error

    if not isfinite(parsed_value):
        raise RuntimeError(
            f"{variable_name} must be finite"
        )

    if parsed_value <= 0:
        raise RuntimeError(
            f"{variable_name} must be "
            "greater than zero"
        )

    return parsed_value