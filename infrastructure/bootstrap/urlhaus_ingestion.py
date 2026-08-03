from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv


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

URLHAUS_AUTH_KEY_ENV = (
    "URLHAUS_AUTH_KEY"
)

DEFAULT_BATCH_SIZE = 500

DEFAULT_TIMEOUT = (
    URLhausConnector.DEFAULT_TIMEOUT
)

DEFAULT_BASE_URL = (
    URLhausConnector.BASE_URL
)


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

    Les dépendances sont créées exclusivement dans ce bootstrap :

    - lecture de la configuration ;
    - construction du connecteur HTTP ;
    - adaptation au port d'ingestion ;
    - construction de l'Unit of Work ;
    - construction du service ;
    - construction du job.

    L'appel fournisseur est exécuté avant les transactions
    PostgreSQL par IngestionService.
    """

    _validate_source_id(
        source_id
    )

    auth_key = (
        _get_required_environment_variable(
            URLHAUS_AUTH_KEY_ENV
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

    unit_of_work = (
        SqlAlchemyUnitOfWork(
            session_factory=(
                session_factory
            ),
        )
    )

    payload_hasher = (
        Sha256PayloadHasher()
    )

    ingestion_service = (
        IngestionService(
            unit_of_work=unit_of_work,
            connector=ingestion_connector,
            payload_hasher=payload_hasher,
            batch_size=batch_size,
        )
    )

    return RawIngestionJob(
        ingestion_service=(
            ingestion_service
        ),
        source_id=source_id,
        source_code=URLHAUS_SOURCE_CODE,
    )


def _validate_source_id(
    source_id: UUID,
) -> None:
    if not isinstance(
        source_id,
        UUID,
    ):
        raise TypeError(
            "source_id must be a UUID"
        )


def _get_required_environment_variable(
    name: str,
) -> str:
    """
    Lit une variable obligatoire sans exposer sa valeur.

    Le message d'erreur contient uniquement le nom public
    de la configuration, jamais son contenu.
    """

    if not isinstance(
        name,
        str,
    ):
        raise TypeError(
            "environment variable name "
            "must be a string"
        )

    normalized_name = (
        name.strip()
    )

    if not normalized_name:
        raise ValueError(
            "environment variable name "
            "must not be empty"
        )

    value = os.environ.get(
        normalized_name
    )

    if not isinstance(
        value,
        str,
    ):
        raise URLhausAuthenticationError(
            "URLhaus Auth-Key is required. "
            f"Set the {URLHAUS_AUTH_KEY_ENV} "
            "environment variable."
        )

    normalized_value = (
        value.strip()
    )

    if not normalized_value:
        raise URLhausAuthenticationError(
            "URLhaus Auth-Key must not "
            "be empty."
        )

    return normalized_value