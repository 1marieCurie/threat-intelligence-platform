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

from application.services.cwe_catalog_sync_service import (
    CWECatalogSyncService,
    MAX_CWE_CATALOG_BATCH_SIZE,
)
from infrastructure.adapters.inbound.cwe_catalog_sync_job import (
    CWECatalogSyncJob,
)
from infrastructure.adapters.outbound.cwe_connector import (
    CWEConnector,
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


CWE_CATALOG_SYNC_BATCH_SIZE_ENV = (
    "CWE_CATALOG_SYNC_BATCH_SIZE"
)

CWE_CATALOG_SYNC_MAX_IDS_ENV = (
    "CWE_CATALOG_SYNC_MAX_IDS"
)

CWE_API_TIMEOUT_SECONDS_ENV = (
    "CWE_API_TIMEOUT_SECONDS"
)

DEFAULT_BATCH_SIZE = (
    MAX_CWE_CATALOG_BATCH_SIZE
)

DEFAULT_MAX_CWE_IDS = 5_000
DEFAULT_API_TIMEOUT_SECONDS = 30


def build_cwe_catalog_sync_job(
) -> CWECatalogSyncJob:
    """
    Assemble le pipeline de synchronisation CWE.

    Composition :

    PostgreSQL
    -> Unit of Work
    -> extraction des références CWE
    -> connecteur MITRE
    -> mapping et persistance
    -> job sécurisé
    """

    # Toute la configuration est validée avant
    # l'ouverture d'une connexion PostgreSQL.
    batch_size = _read_positive_integer(
        variable_name=(
            CWE_CATALOG_SYNC_BATCH_SIZE_ENV
        ),
        default=DEFAULT_BATCH_SIZE,
    )

    max_cwe_ids = _read_positive_integer(
        variable_name=(
            CWE_CATALOG_SYNC_MAX_IDS_ENV
        ),
        default=DEFAULT_MAX_CWE_IDS,
    )

    api_timeout_seconds = (
        _read_positive_integer(
            variable_name=(
                CWE_API_TIMEOUT_SECONDS_ENV
            ),
            default=(
                DEFAULT_API_TIMEOUT_SECONDS
            ),
        )
    )

    if (
        batch_size
        > MAX_CWE_CATALOG_BATCH_SIZE
    ):
        raise RuntimeError(
            f"{CWE_CATALOG_SYNC_BATCH_SIZE_ENV} "
            "must not exceed "
            f"{MAX_CWE_CATALOG_BATCH_SIZE}"
        )

    engine = create_ingestion_engine()

    session_factory = create_session_factory(
        engine
    )

    unit_of_work = SqlAlchemyUnitOfWork(
        session_factory=session_factory,
    )

    client = CWEConnector(
        timeout=api_timeout_seconds,
    )

    sync_service = CWECatalogSyncService(
        client=client,
        unit_of_work=unit_of_work,
        batch_size=batch_size,
        max_cwe_ids=max_cwe_ids,
    )

    return CWECatalogSyncJob(
        sync_service=sync_service,
    )


def _read_positive_integer(
    *,
    variable_name: str,
    default: int,
) -> int:
    """
    Lit une variable d'environnement entière positive.

    Une configuration invalide provoque un échec immédiat,
    avant toute connexion réseau ou PostgreSQL.
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