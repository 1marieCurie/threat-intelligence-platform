from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

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


import pytest
from sqlalchemy import (
    create_engine,
    delete,
    select,
    text,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import (
    Session,
    sessionmaker,
)

from application.ports.outbound.ingestion_run_payload_repository import (
    IngestionRunPayloadLink,
)
from application.ports.outbound.raw_payload_repository import (
    RawPayloadData,
)
from application.services.urlhaus_normalization_service import (
    URLhausNormalizationService,
)
from application.services.urlhaus_normalizer import (
    URLhausNormalizer,
)
from infrastructure.persistence.models.normalized_urlhaus import (
    URLhausURLModel,
)
from infrastructure.persistence.models.ops import (
    IngestionRunModel,
    SourceModel,
)
from infrastructure.persistence.models.raw import (
    SourcePayloadModel,
)
from infrastructure.persistence.sqlalchemy import (
    SqlAlchemyUnitOfWork,
    create_ingestion_engine,
    create_session_factory,
)


pytestmark = pytest.mark.integration


class _FailingMarkProcessedRepository:
    """
    Décorateur simulant un échec du passage à processed.

    Toutes les autres opérations sont déléguées au véritable
    repository PostgreSQL.
    """

    def __init__(
        self,
        repository: object,
    ) -> None:
        self._repository = repository

    def mark_processed(
        self,
        *,
        payload_id: UUID,
    ) -> bool:
        del payload_id
        return False

    def __getattr__(
        self,
        name: str,
    ) -> Any:
        return getattr(
            self._repository,
            name,
        )


class _FailingMarkProcessedUnitOfWork(
    SqlAlchemyUnitOfWork
):
    def __enter__(
        self,
    ) -> "_FailingMarkProcessedUnitOfWork":
        super().__enter__()

        self.raw_payloads = (
            _FailingMarkProcessedRepository(
                self.raw_payloads
            )
        )  # type: ignore[assignment]

        return self


@dataclass(
    frozen=True,
    slots=True,
)
class _IntegrationContext:
    source_id: UUID
    ingestion_run_id: UUID

    owner_engine: Engine
    owner_session_factory: sessionmaker[Session]

    ingestion_engine: Engine
    ingestion_session_factory: sessionmaker[Session]


def _create_owner_database(
) -> tuple[
    Engine,
    sessionmaker[Session],
]:
    database_url = os.environ.get(
        "MIGRATION_DATABASE_URL"
    )

    if not database_url:
        raise RuntimeError(
            "MIGRATION_DATABASE_URL is not defined"
        )

    engine = create_engine(
        database_url,
        pool_pre_ping=True,
    )

    session_factory = sessionmaker(
        bind=engine,
        class_=Session,
        autoflush=False,
        expire_on_commit=False,
    )

    return (
        engine,
        session_factory,
    )


def _create_source_and_completed_run(
    *,
    owner_session_factory: sessionmaker[Session],
    ingestion_session_factory: sessionmaker[Session],
    source_id: UUID,
    ingestion_run_id: UUID,
) -> None:
    source_code = (
        "TEST_URLHAUS_NORM_"
        f"{uuid4().hex[:16]}"
    )

    with owner_session_factory() as session:
        session.execute(
            text(
                "SET ROLE threat_intel_owner"
            )
        )

        session.add(
            SourceModel(
                id=source_id,
                code=source_code,
                name=(
                    "URLhaus normalization "
                    "integration test"
                ),
            )
        )

        session.commit()

    with ingestion_session_factory() as session:
        session.add(
            IngestionRunModel(
                id=ingestion_run_id,
                source_id=source_id,
                status="completed",
            )
        )

        session.commit()


def _save_pending_payload(
    *,
    ingestion_session_factory: sessionmaker[Session],
    source_id: UUID,
    ingestion_run_id: UUID,
    urlhaus_id: int,
    payload: dict[str, object],
) -> UUID:
    unit_of_work = SqlAlchemyUnitOfWork(
        session_factory=(
            ingestion_session_factory
        ),
    )

    with unit_of_work:
        payload_id = (
            unit_of_work.raw_payloads.save(
                RawPayloadData(
                    source_id=source_id,
                    ingestion_run_id=(
                        ingestion_run_id
                    ),
                    external_record_id=str(
                        urlhaus_id
                    ),
                    request_url=(
                        "https://urlhaus-api."
                        "abuse.ch/v1/urls/recent/"
                    ),
                    payload=payload,
                    payload_hash=(
                        uuid4().hex * 2
                    ),
                    http_status=200,
                    processing_status="pending",
                )
            )
        )

        link_result = (
            unit_of_work
            .ingestion_run_payloads
            .link_many_ignore_existing(
                (
                    IngestionRunPayloadLink(
                        ingestion_run_id=(
                            ingestion_run_id
                        ),
                        raw_payload_id=(
                            payload_id
                        ),
                    ),
                )
            )
        )

        if (
            link_result.unique_count != 1
            or link_result.inserted_count != 1
        ):
            raise RuntimeError(
                "Unable to create the "
                "run/payload observation"
            )

        unit_of_work.commit()

    return payload_id


def _delete_test_data(
    *,
    owner_session_factory: sessionmaker[Session],
    source_id: UUID,
) -> None:
    with owner_session_factory() as session:
        session.execute(
            text(
                "SET ROLE threat_intel_owner"
            )
        )

        run_ids = (
            select(
                IngestionRunModel.id
            )
            .where(
                IngestionRunModel.source_id
                == source_id
            )
        )

        payload_ids = (
            select(
                SourcePayloadModel.id
            )
            .where(
                SourcePayloadModel
                .ingestion_run_id
                .in_(run_ids)
            )
        )

        # La FK normalized -> raw utilise RESTRICT.
        # La couche normalisée doit donc être supprimée avant raw.
        session.execute(
            delete(
                URLhausURLModel
            ).where(
                URLhausURLModel
                .raw_payload_id
                .in_(payload_ids)
            )
        )

        session.execute(
            delete(
                SourcePayloadModel
            ).where(
                SourcePayloadModel
                .ingestion_run_id
                .in_(run_ids)
            )
        )

        session.execute(
            delete(
                IngestionRunModel
            ).where(
                IngestionRunModel.source_id
                == source_id
            )
        )

        session.execute(
            delete(
                SourceModel
            ).where(
                SourceModel.id
                == source_id
            )
        )

        session.commit()


@pytest.fixture
def integration_context(
) -> Iterator[_IntegrationContext]:
    source_id = uuid4()
    ingestion_run_id = uuid4()

    (
        owner_engine,
        owner_session_factory,
    ) = _create_owner_database()

    ingestion_engine = (
        create_ingestion_engine()
    )

    ingestion_session_factory = (
        create_session_factory(
            ingestion_engine
        )
    )

    _create_source_and_completed_run(
        owner_session_factory=(
            owner_session_factory
        ),
        ingestion_session_factory=(
            ingestion_session_factory
        ),
        source_id=source_id,
        ingestion_run_id=ingestion_run_id,
    )

    context = _IntegrationContext(
        source_id=source_id,
        ingestion_run_id=ingestion_run_id,
        owner_engine=owner_engine,
        owner_session_factory=(
            owner_session_factory
        ),
        ingestion_engine=ingestion_engine,
        ingestion_session_factory=(
            ingestion_session_factory
        ),
    )

    try:
        yield context

    finally:
        _delete_test_data(
            owner_session_factory=(
                owner_session_factory
            ),
            source_id=source_id,
        )

        ingestion_engine.dispose()
        owner_engine.dispose()


def _build_service(
    context: _IntegrationContext,
    *,
    unit_of_work_class: type[
        SqlAlchemyUnitOfWork
    ] = SqlAlchemyUnitOfWork,
) -> URLhausNormalizationService:
    unit_of_work = unit_of_work_class(
        session_factory=(
            context
            .ingestion_session_factory
        ),
    )

    return URLhausNormalizationService(
        unit_of_work=unit_of_work,
        normalizer=URLhausNormalizer(),
    )


def test_process_pending_persists_normalized_url(
    integration_context: _IntegrationContext,
) -> None:
    urlhaus_id = (
        uuid4().int
        % 9_000_000_000
        + 1
    )

    payload_id = _save_pending_payload(
        ingestion_session_factory=(
            integration_context
            .ingestion_session_factory
        ),
        source_id=(
            integration_context.source_id
        ),
        ingestion_run_id=(
            integration_context
            .ingestion_run_id
        ),
        urlhaus_id=urlhaus_id,
        payload={
            "id": str(urlhaus_id),
            "url": (
                "https://payload.example.invalid/"
                "malware/download"
            ),
            "url_status": "ONLINE",
            "date_added": (
                "2026-08-03 12:01:36 UTC"
            ),
            "threat": "MALWARE_DOWNLOAD",
            "reporter": "integration-test",
            "larted": "yes",
            "tags": [
                "elf",
                "mirai",
                "elf",
            ],
        },
    )

    service = _build_service(
        integration_context
    )

    result = service.process_pending(
        source_id=(
            integration_context.source_id
        ),
        limit=10,
    )

    assert result.claimed == 1
    assert result.normalized == 1
    assert result.already_normalized == 0
    assert result.failed == 0
    assert result.requeued == 0
    assert result.stale_failed == 0

    with (
        integration_context
        .ingestion_session_factory()
    ) as session:
        raw_payload = session.get(
            SourcePayloadModel,
            payload_id,
        )

        normalized = (
            session.execute(
                select(
                    URLhausURLModel
                ).where(
                    URLhausURLModel
                    .raw_payload_id
                    == payload_id
                )
            )
            .scalar_one_or_none()
        )

        assert raw_payload is not None

        assert (
            raw_payload.processing_status
            == "processed"
        )

        assert (
            raw_payload.processing_started_at
            is None
        )

        assert (
            raw_payload.processing_attempts
            == 1
        )

        assert (
            raw_payload.error_message
            is None
        )

        assert normalized is not None
        assert normalized.urlhaus_id == urlhaus_id

        assert normalized.hostname == (
            "payload.example.invalid"
        )

        assert (
            normalized.url_status
            == "online"
        )

        assert (
            normalized.threat_type
            == "malware_download"
        )

        assert (
            normalized.reporter
            == "integration-test"
        )

        assert normalized.larted is True

        assert normalized.tags == [
            "elf",
            "mirai",
        ]

        assert normalized.blacklists == []

        assert (
            normalized.normalizer_version
            == "1.0.0"
        )

        assert normalized.date_added is not None
        assert normalized.normalized_at is not None

    second_result = service.process_pending(
        source_id=(
            integration_context.source_id
        ),
        limit=10,
    )

    assert second_result.claimed == 0
    assert second_result.normalized == 0
    assert (
        second_result.already_normalized
        == 0
    )
    assert second_result.failed == 0


def test_invalid_payload_is_failed_without_ioc_leak(
    integration_context: _IntegrationContext,
) -> None:
    urlhaus_id = (
        uuid4().int
        % 9_000_000_000
        + 1
    )

    sensitive_url = (
        "ftp://user:super-secret@"
        "example.invalid/file?"
        "access_token=private-value"
    )

    payload_id = _save_pending_payload(
        ingestion_session_factory=(
            integration_context
            .ingestion_session_factory
        ),
        source_id=(
            integration_context.source_id
        ),
        ingestion_run_id=(
            integration_context
            .ingestion_run_id
        ),
        urlhaus_id=urlhaus_id,
        payload={
            "id": urlhaus_id,
            "url": sensitive_url,
        },
    )

    service = _build_service(
        integration_context
    )

    result = service.process_pending(
        source_id=(
            integration_context.source_id
        ),
        limit=10,
    )

    assert result.claimed == 1
    assert result.normalized == 0
    assert result.failed == 1

    with (
        integration_context
        .ingestion_session_factory()
    ) as session:
        raw_payload = session.get(
            SourcePayloadModel,
            payload_id,
        )

        normalized = (
            session.execute(
                select(
                    URLhausURLModel
                ).where(
                    URLhausURLModel
                    .raw_payload_id
                    == payload_id
                )
            )
            .scalar_one_or_none()
        )

        assert raw_payload is not None

        assert (
            raw_payload.processing_status
            == "failed"
        )

        assert (
            raw_payload.processing_started_at
            is None
        )

        assert (
            raw_payload.processing_attempts
            == 1
        )

        assert (
            raw_payload.error_message
            is not None
        )

        error_message = (
            raw_payload.error_message
        )

        assert sensitive_url not in error_message
        assert "super-secret" not in error_message
        assert "private-value" not in error_message
        assert "example.invalid" not in error_message

        assert (
            "URLhausNormalizationError"
            in error_message
        )

        assert normalized is None


def test_normalized_insert_is_rolled_back_when_status_update_fails(
    integration_context: _IntegrationContext,
) -> None:
    urlhaus_id = (
        uuid4().int
        % 9_000_000_000
        + 1
    )

    payload_id = _save_pending_payload(
        ingestion_session_factory=(
            integration_context
            .ingestion_session_factory
        ),
        source_id=(
            integration_context.source_id
        ),
        ingestion_run_id=(
            integration_context
            .ingestion_run_id
        ),
        urlhaus_id=urlhaus_id,
        payload={
            "id": urlhaus_id,
            "url": (
                "https://rollback.example.invalid/"
                "malware"
            ),
            "url_status": "online",
            "date_added": (
                "2026-08-03 12:01:36 UTC"
            ),
            "threat": "malware_download",
            "larted": False,
        },
    )

    service = _build_service(
        integration_context,
        unit_of_work_class=(
            _FailingMarkProcessedUnitOfWork
        ),
    )

    result = service.process_pending(
        source_id=(
            integration_context.source_id
        ),
        limit=10,
    )

    assert result.claimed == 1
    assert result.normalized == 0
    assert result.failed == 1

    with (
        integration_context
        .ingestion_session_factory()
    ) as session:
        raw_payload = session.get(
            SourcePayloadModel,
            payload_id,
        )

        normalized = (
            session.execute(
                select(
                    URLhausURLModel
                ).where(
                    URLhausURLModel
                    .raw_payload_id
                    == payload_id
                )
            )
            .scalar_one_or_none()
        )

        assert raw_payload is not None

        assert (
            raw_payload.processing_status
            == "failed"
        )

        assert (
            raw_payload.processing_started_at
            is None
        )

        assert (
            raw_payload.processing_attempts
            == 1
        )

        assert raw_payload.error_message == (
            "RuntimeError: unexpected "
            "normalization failure"
        )

        # L'insertion normalisée et le passage à processed
        # appartiennent à la même transaction.
        assert normalized is None