from __future__ import annotations

import os
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, delete, select, text
from sqlalchemy.orm import Session, sessionmaker

from application.ports.outbound.ingestion_connector import (
    FetchedRecord,
    FetchResult,
)
from application.services.ingestion_service import (
    IngestionService,
)
from infrastructure.persistence.models.ops import (
    IngestionRunModel,
    SourceModel,
    SyncStateModel,
)
from infrastructure.persistence.models.raw import (
    SourcePayloadModel,
)
from infrastructure.persistence.sqlalchemy import (
    SqlAlchemyUnitOfWork,
    create_ingestion_engine,
    create_session_factory,
)
from infrastructure.security.sha256_payload_hasher import (
    Sha256PayloadHasher,
)


pytestmark = pytest.mark.integration


class SuccessfulConnector:
    def fetch(
        self,
        *,
        cursor: str | None,
    ) -> FetchResult:
        assert cursor is None

        return FetchResult(
            records=[
                FetchedRecord(
                    external_record_id="CVE-2026-TEST-0001",
                    payload={
                        "id": "CVE-2026-TEST-0001",
                        "severity": "high",
                    },
                    http_status=200,
                )
            ],
            next_cursor="cursor-001",
            metadata={
                "page": 1,
            },
            connector_version="test-1.0.0",
        )


class FailingConnector:
    def fetch(
        self,
        *,
        cursor: str | None,
    ) -> FetchResult:
        raise RuntimeError(
            "Simulated connector failure"
        )
def _create_owner_session_factory() -> sessionmaker[Session]:
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

    return sessionmaker(
        bind=engine,
        class_=Session,
        autoflush=False,
        expire_on_commit=False,
    )


def _create_source(
    *,
    owner_session_factory: sessionmaker[Session],
    source_id: UUID,
    source_code: str,
) -> None:
    with owner_session_factory() as session:
        session.execute(
            text("SET ROLE threat_intel_owner")
        )

        session.add(
            SourceModel(
                id=source_id,
                code=source_code,
                name="Ingestion service integration test",
            )
        )

        session.commit()


def _delete_test_data(
    *,
    owner_session_factory: sessionmaker[Session],
    source_id: UUID,
) -> None:
    with owner_session_factory() as session:
        session.execute(
            text("SET ROLE threat_intel_owner")
        )

        run_ids = select(
            IngestionRunModel.id
        ).where(
            IngestionRunModel.source_id == source_id
        )

        session.execute(
            delete(SourcePayloadModel).where(
                SourcePayloadModel.ingestion_run_id.in_(
                    run_ids
                )
            )
        )

        session.execute(
            delete(SyncStateModel).where(
                SyncStateModel.source_id == source_id
            )
        )

        session.execute(
            delete(IngestionRunModel).where(
                IngestionRunModel.source_id == source_id
            )
        )

        session.execute(
            delete(SourceModel).where(
                SourceModel.id == source_id
            )
        )

        session.commit()

def test_ingestion_service_persists_complete_flow() -> None:
    source_id = uuid4()
    source_code = f"SERVICE_OK_{uuid4().hex[:20]}"

    owner_session_factory = (
        _create_owner_session_factory()
    )

    ingestion_engine = create_ingestion_engine()
    ingestion_session_factory = create_session_factory(
        ingestion_engine
    )

    _create_source(
        owner_session_factory=owner_session_factory,
        source_id=source_id,
        source_code=source_code,
    )

    try:
        service = IngestionService(
            unit_of_work=SqlAlchemyUnitOfWork(
                session_factory=ingestion_session_factory,
            ),
            connector=SuccessfulConnector(),
            payload_hasher=Sha256PayloadHasher(),
        )

        result = service.ingest(
            source_id=source_id,
        )

        assert result.status == "completed"
        assert result.records_received == 1
        assert result.records_persisted == 1
        assert result.records_skipped == 0

        with ingestion_session_factory() as session:
            persisted_run = session.get(
                IngestionRunModel,
                result.run_id,
            )

            persisted_state = session.get(
                SyncStateModel,
                source_id,
            )

            persisted_payload = session.execute(
                select(SourcePayloadModel).where(
                    SourcePayloadModel.ingestion_run_id
                    == result.run_id
                )
            ).scalar_one_or_none()

            assert persisted_run is not None
            assert persisted_run.status == "completed"
            assert persisted_run.records_received == 1
            assert persisted_run.records_succeeded == 1
            assert persisted_run.records_failed == 0

            assert persisted_payload is not None
            assert (
                persisted_payload.external_record_id
                == "CVE-2026-TEST-0001"
            )
            assert len(
                persisted_payload.payload_hash
            ) == 64

            assert persisted_state is not None
            assert persisted_state.cursor == "cursor-001"
            assert persisted_state.metadata_ == {
                "page": 1,
            }

    finally:
        _delete_test_data(
            owner_session_factory=owner_session_factory,
            source_id=source_id,
        )
def test_ingestion_service_marks_run_failed_on_connector_error() -> None:
    source_id = uuid4()
    source_code = f"SERVICE_FAIL_{uuid4().hex[:18]}"

    owner_session_factory = (
        _create_owner_session_factory()
    )

    ingestion_engine = create_ingestion_engine()
    ingestion_session_factory = create_session_factory(
        ingestion_engine
    )

    _create_source(
        owner_session_factory=owner_session_factory,
        source_id=source_id,
        source_code=source_code,
    )

    try:
        service = IngestionService(
            unit_of_work=SqlAlchemyUnitOfWork(
                session_factory=ingestion_session_factory,
            ),
            connector=FailingConnector(),
            payload_hasher=Sha256PayloadHasher(),
        )

        with pytest.raises(
            RuntimeError,
            match="Simulated connector failure",
        ):
            service.ingest(
                source_id=source_id,
            )

        with ingestion_session_factory() as session:
            persisted_run = session.execute(
                select(IngestionRunModel).where(
                    IngestionRunModel.source_id
                    == source_id
                )
            ).scalar_one_or_none()

            persisted_state = session.get(
                SyncStateModel,
                source_id,
            )

            persisted_payloads = session.execute(
                select(SourcePayloadModel).where(
                    SourcePayloadModel.source_id
                    == source_id
                )
            ).scalars().all()

            assert persisted_run is not None
            assert persisted_run.status == "failed"
            assert persisted_run.finished_at is not None
            assert (
                persisted_run.error_summary
                == (
                    "RuntimeError: "
                    "Simulated connector failure"
                )
            )

            assert persisted_state is None
            assert persisted_payloads == []

    finally:
        _delete_test_data(
            owner_session_factory=owner_session_factory,
            source_id=source_id,
        )