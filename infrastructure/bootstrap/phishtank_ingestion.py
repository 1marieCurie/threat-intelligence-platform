from __future__ import annotations

from dotenv import find_dotenv, load_dotenv

load_dotenv(
    dotenv_path=find_dotenv(usecwd=True),
    override=False,
)


import os
from uuid import UUID

from application.services.ingestion_service import (
    IngestionService,
)
from infrastructure.adapters.inbound.raw_ingestion_job import (
    RawIngestionJob,
)
from infrastructure.adapters.outbound.phishtank.phishtank_ingestion_connector import (
    PhishTankIngestionConnector,
)
from infrastructure.adapters.outbound.phishtank_connector import (
    PhishTankConnector,
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
from infrastructure.security.sha256_payload_hasher import (
    Sha256PayloadHasher,
)


PHISHTANK_SOURCE_CODE = "PHISHTANK"

DEFAULT_STORAGE_DIRECTORY = (
    "data/phishtank"
)

DEFAULT_BATCH_SIZE = 500


def build_phishtank_ingestion_job(
    *,
    source_id: UUID,
    limit: int | None = None,
    force_download: bool = False,
    batch_size: int = DEFAULT_BATCH_SIZE,
) -> RawIngestionJob:
    """
    Assemble le pipeline d'ingestion brute PhishTank.

    Le téléchargement du snapshot est effectué avant
    l'ouverture des transactions PostgreSQL.
    """
    if not isinstance(
        source_id,
        UUID,
    ):
        raise TypeError(
            "source_id must be a UUID"
        )

    app_key = (
        _get_optional_environment_variable(
            "PHISHTANK_APP_KEY"
        )
    )

    storage_directory = (
        _get_optional_environment_variable(
            "PHISHTANK_STORAGE_DIRECTORY"
        )
        or DEFAULT_STORAGE_DIRECTORY
    )

    source_connector = PhishTankConnector(
        storage_directory=(
            storage_directory
        ),
        app_key=app_key,
    )

    ingestion_connector = (
        PhishTankIngestionConnector(
            connector=source_connector,
            limit=limit,
            force_download=(
                force_download
            ),
        )
    )

    engine = create_ingestion_engine()

    session_factory = (
        create_session_factory(
            engine
        )
    )

    unit_of_work = SqlAlchemyUnitOfWork(
        session_factory=session_factory,
    )

    ingestion_service = IngestionService(
        unit_of_work=unit_of_work,
        connector=ingestion_connector,
        payload_hasher=(
            Sha256PayloadHasher()
        ),
        batch_size=batch_size,
    )

    return RawIngestionJob(
        ingestion_service=(
            ingestion_service
        ),
        source_id=source_id,
        source_code=(
            PHISHTANK_SOURCE_CODE
        ),
    )


def _get_optional_environment_variable(
    name: str,
) -> str | None:
    value = os.getenv(
        name
    )

    if value is None:
        return None

    normalized = value.strip()

    return normalized or None