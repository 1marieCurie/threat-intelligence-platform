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
from infrastructure.adapters.outbound.urlhaus.urlhaus_ingestion_connector import (
    URLhausIngestionConnector,
)
from infrastructure.adapters.outbound.urlhaus_connector import (
    URLhausAuthenticationError,
    URLhausConnector,
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


URLHAUS_SOURCE_CODE = "URLHAUS"

DEFAULT_BATCH_SIZE = 500
DEFAULT_TIMEOUT = URLhausConnector.DEFAULT_TIMEOUT
DEFAULT_BASE_URL = URLhausConnector.BASE_URL


def build_urlhaus_ingestion_job(
    *,
    source_id: UUID,
    limit: int | None = None,
    batch_size: int = DEFAULT_BATCH_SIZE,
    timeout: float = DEFAULT_TIMEOUT,
    base_url: str = DEFAULT_BASE_URL,
) -> RawIngestionJob:
    """
    Assemble le pipeline d'ingestion brute URLhaus.

    L'appel URLhaus est effectué par IngestionService avant
    l'ouverture des transactions PostgreSQL.

    La clé d'authentification est résolue uniquement dans ce
    bootstrap puis injectée explicitement dans le connecteur.
    """

    if not isinstance(
        source_id,
        UUID,
    ):
        raise TypeError(
            "source_id must be a UUID"
        )

    auth_key = (
        _get_required_environment_variable(
            "URLHAUS_AUTH_KEY"
        )
    )

    source_connector = URLhausConnector(
        auth_key=auth_key,
        timeout=timeout,
        base_url=base_url,
    )

    ingestion_connector = (
        URLhausIngestionConnector(
            connector=source_connector,
            limit=limit,
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

    payload_hasher = (
        Sha256PayloadHasher()
    )

    ingestion_service = IngestionService(
        unit_of_work=unit_of_work,
        connector=ingestion_connector,
        payload_hasher=payload_hasher,
        batch_size=batch_size,
    )

    return RawIngestionJob(
        ingestion_service=ingestion_service,
        source_id=source_id,
        source_code=URLHAUS_SOURCE_CODE,
    )


def _get_required_environment_variable(
    name: str,
) -> str:
    value = os.getenv(
        name
    )

    if not isinstance(
        value,
        str,
    ):
        raise URLhausAuthenticationError(
            "URLhaus Auth-Key is required. "
            "Set the URLHAUS_AUTH_KEY "
            "environment variable."
        )

    normalized_value = value.strip()

    if not normalized_value:
        raise URLhausAuthenticationError(
            "URLhaus Auth-Key must not "
            "be empty."
        )

    return normalized_value