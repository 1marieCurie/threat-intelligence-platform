import os
from uuid import UUID

from application.services.ingestion_service import (
    IngestionService,
)
from infrastructure.adapters.inbound.github_advisory_raw_ingestion_job import (
    GitHubAdvisoryRawIngestionJob,
)
from infrastructure.adapters.outbound.github.github_advisory_ingestion_connector import (
    GitHubAdvisoryIngestionConnector,
)
from infrastructure.adapters.outbound.github_advisory_connector import (
    GitHubAdvisoryConnector,
)
from infrastructure.persistence.sqlalchemy.unit_of_work import (
    SqlAlchemyUnitOfWork,
)
from infrastructure.persistence.sqlalchemy.engine import create_ingestion_engine

from infrastructure.persistence.sqlalchemy.session import create_session_factory

from infrastructure.security.sha256_payload_hasher import (
    Sha256PayloadHasher,
)


def build_github_advisory_ingestion_job(
    *,
    source_id: UUID,
) -> GitHubAdvisoryRawIngestionJob:
    if not isinstance(source_id, UUID):
        raise TypeError(
            "source_id must be a UUID"
        )

    github_token = _get_optional_environment_variable(
        "GITHUB_TOKEN"
    )

    github_connector = GitHubAdvisoryConnector(
        token=github_token,
    )

    ingestion_connector = (
        GitHubAdvisoryIngestionConnector(
            connector=github_connector,
        )
    )

    engine = create_ingestion_engine()
    session_factory = create_session_factory(
        engine
    )

    unit_of_work = SqlAlchemyUnitOfWork(
        session_factory=session_factory,
    )

    ingestion_service = IngestionService(
        unit_of_work=unit_of_work,
        connector=ingestion_connector,
        payload_hasher=Sha256PayloadHasher(),
    )

    return GitHubAdvisoryRawIngestionJob(
        ingestion_service=ingestion_service,
        source_id=source_id,
    )


def _get_optional_environment_variable(
    name: str,
) -> str | None:
    value = os.getenv(name)

    if value is None:
        return None

    normalized = value.strip()

    return normalized or None