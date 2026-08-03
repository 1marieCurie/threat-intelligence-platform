from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)

ENV_FILE = PROJECT_ROOT / ".env"

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
from infrastructure.adapters.outbound.github.github_advisory_ingestion_connector import (
    GitHubAdvisoryIngestionConnector,
)
from infrastructure.adapters.outbound.github_advisory_connector import (
    GitHubAdvisoryConnector,
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


GITHUB_ADVISORY_SOURCE_CODE = (
    "GITHUB_ADVISORY"
)

GITHUB_TOKEN_ENV = "GITHUB_TOKEN"


def build_github_advisory_ingestion_job(
    *,
    source_id: UUID,
) -> RawIngestionJob:
    """
    Assemble le pipeline d'ingestion brute
    GitHub Advisory.

    Le bootstrap est le seul composant autorisé
    à lire les variables d'environnement et à
    construire les dépendances infrastructurelles.
    """

    if not isinstance(source_id, UUID):
        raise TypeError(
            "source_id must be a UUID"
        )

    github_token = (
        _get_optional_environment_variable(
            GITHUB_TOKEN_ENV
        )
    )

    github_connector = (
        GitHubAdvisoryConnector(
            token=github_token,
        )
    )

    ingestion_connector = (
        GitHubAdvisoryIngestionConnector(
            connector=github_connector,
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
    )

    return RawIngestionJob(
        ingestion_service=(
            ingestion_service
        ),
        source_id=source_id,
        source_code=(
            GITHUB_ADVISORY_SOURCE_CODE
        ),
    )


def _get_optional_environment_variable(
    name: str,
) -> str | None:
    if not isinstance(name, str):
        raise TypeError(
            "name must be a string"
        )

    normalized_name = name.strip()

    if not normalized_name:
        raise ValueError(
            "name must not be empty"
        )

    value = os.getenv(
        normalized_name
    )

    if value is None:
        return None

    normalized_value = value.strip()

    return normalized_value or None