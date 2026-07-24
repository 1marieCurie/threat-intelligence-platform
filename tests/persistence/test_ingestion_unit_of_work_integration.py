from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, delete, select, text
from sqlalchemy.orm import Session, sessionmaker

from application.ports.outbound.ingestion_run_repository import (
    IngestionRunData,
)
from application.ports.outbound.raw_payload_repository import (
    RawPayloadData,
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
from application.ports.outbound.sync_state_repository import (
    SyncStateData,
)


pytestmark = pytest.mark.integration


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
                name="Ingestion UoW integration test",
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
            delete(IngestionRunModel).where(
                IngestionRunModel.source_id == source_id
            )
        )

        session.execute(
            delete(SyncStateModel).where(
                SyncStateModel.source_id == source_id
            )
        )

        session.execute(
            delete(SourceModel).where(
                SourceModel.id == source_id
            )
        )

        session.commit()

def test_uow_creates_run_payload_and_marks_completed() -> None:
    source_id = uuid4()
    source_code = (
        f"UOW_FLOW_{uuid4().hex[:20]}"
    )
    external_record_id = (
        f"RECORD-{uuid4()}"
    )

    owner_session_factory = (
        _create_owner_session_factory()
    )

    ingestion_engine = create_ingestion_engine()
    ingestion_session_factory = (
        create_session_factory(
            ingestion_engine
        )
    )

    _create_source(
        owner_session_factory=owner_session_factory,
        source_id=source_id,
        source_code=source_code,
    )

    run_id: UUID | None = None
    payload_id: UUID | None = None

    try:
        unit_of_work = SqlAlchemyUnitOfWork(
            session_factory=(
                ingestion_session_factory
            ),
        )

        with unit_of_work:
            run_id = (
                unit_of_work.ingestion_runs.create(
                    IngestionRunData(
                        source_id=source_id,
                        status="running",
                        connector_version="1.0.0",
                    )
                )
            )

            payload_id = (
                unit_of_work.raw_payloads.save(
                    RawPayloadData(
                        source_id=source_id,
                        ingestion_run_id=run_id,
                        external_record_id=(
                            external_record_id
                        ),
                        payload={
                            "id": external_record_id,
                        },
                        payload_hash="d" * 64,
                        http_status=200,
                    )
                )
            )

            updated = (
                unit_of_work.ingestion_runs
                .mark_completed(
                    run_id=run_id,
                    finished_at=datetime.now(UTC),
                    records_received=1,
                    records_succeeded=1,
                    records_failed=0,
                )
            )

            assert updated is True

            unit_of_work.commit()

        with ingestion_session_factory() as session:
            persisted_run = session.get(
                IngestionRunModel,
                run_id,
            )

            persisted_payload = session.get(
                SourcePayloadModel,
                payload_id,
            )

            assert persisted_run is not None
            assert persisted_run.status == "completed"
            assert persisted_run.finished_at is not None
            assert persisted_run.records_received == 1
            assert persisted_run.records_succeeded == 1
            assert persisted_run.records_failed == 0

            assert persisted_payload is not None
            assert (
                persisted_payload.ingestion_run_id
                == run_id
            )
            assert (
                persisted_payload.external_record_id
                == external_record_id
            )

    finally:
        _delete_test_data(
            owner_session_factory=(
                owner_session_factory
            ),
            source_id=source_id,
        )
def test_uow_rolls_back_run_and_payload_on_exception() -> None:
    source_id = uuid4()
    source_code = (
        f"UOW_FAIL_{uuid4().hex[:20]}"
    )
    external_record_id = (
        f"RECORD-{uuid4()}"
    )

    owner_session_factory = (
        _create_owner_session_factory()
    )

    ingestion_engine = create_ingestion_engine()
    ingestion_session_factory = (
        create_session_factory(
            ingestion_engine
        )
    )

    _create_source(
        owner_session_factory=owner_session_factory,
        source_id=source_id,
        source_code=source_code,
    )

    run_id: UUID | None = None
    payload_id: UUID | None = None

    try:
        unit_of_work = SqlAlchemyUnitOfWork(
            session_factory=(
                ingestion_session_factory
            ),
        )

        with pytest.raises(
            RuntimeError,
            match="forced ingestion failure",
        ):
            with unit_of_work:
                run_id = (
                    unit_of_work.ingestion_runs.create(
                        IngestionRunData(
                            source_id=source_id,
                            status="running",
                        )
                    )
                )

                payload_id = (
                    unit_of_work.raw_payloads.save(
                        RawPayloadData(
                            source_id=source_id,
                            ingestion_run_id=run_id,
                            external_record_id=(
                                external_record_id
                            ),
                            payload={
                                "id": external_record_id,
                            },
                            payload_hash="e" * 64,
                            http_status=200,
                        )
                    )
                )

                raise RuntimeError(
                    "forced ingestion failure"
                )

        with ingestion_session_factory() as session:
            assert session.get(
                IngestionRunModel,
                run_id,
            ) is None

            assert session.get(
                SourcePayloadModel,
                payload_id,
            ) is None

    finally:
        _delete_test_data(
            owner_session_factory=(
                owner_session_factory
            ),
            source_id=source_id,
        )
def test_uow_persists_complete_ingestion_flow() -> None:
    source_id = uuid4()
    source_code = f"UOW_SYNC_{uuid4().hex[:20]}"
    external_record_id = f"RECORD-{uuid4()}"

    owner_session_factory = (
        _create_owner_session_factory()
    )

    ingestion_engine = create_ingestion_engine()
    ingestion_session_factory = (
        create_session_factory(
            ingestion_engine
        )
    )

    _create_source(
        owner_session_factory=owner_session_factory,
        source_id=source_id,
        source_code=source_code,
    )

    run_id: UUID | None = None
    payload_id: UUID | None = None

    completed_at = datetime.now(UTC)

    try:
        unit_of_work = SqlAlchemyUnitOfWork(
            session_factory=ingestion_session_factory,
        )

        with unit_of_work:
            unit_of_work.sync_states.mark_attempt(
                source_id=source_id,
                attempted_at=completed_at,
            )

            run_id = unit_of_work.ingestion_runs.create(
                IngestionRunData(
                    source_id=source_id,
                    status="running",
                    connector_version="1.0.0",
                )
            )

            payload_id = unit_of_work.raw_payloads.save(
                RawPayloadData(
                    source_id=source_id,
                    ingestion_run_id=run_id,
                    external_record_id=external_record_id,
                    payload={
                        "id": external_record_id,
                    },
                    payload_hash="f" * 64,
                    http_status=200,
                )
            )

            unit_of_work.sync_states.upsert(
                SyncStateData(
                    source_id=source_id,
                    cursor="cursor-002",
                    last_attempt_at=completed_at,
                    last_success_at=completed_at,
                    metadata={
                        "page": 2,
                    },
                )
            )

            updated = (
                unit_of_work.ingestion_runs.mark_completed(
                    run_id=run_id,
                    finished_at=completed_at,
                    records_received=1,
                    records_succeeded=1,
                    records_failed=0,
                )
            )

            assert updated is True

            unit_of_work.commit()

        with ingestion_session_factory() as session:
            persisted_run = session.get(
                IngestionRunModel,
                run_id,
            )

            persisted_payload = session.get(
                SourcePayloadModel,
                payload_id,
            )

            persisted_state = session.get(
                SyncStateModel,
                source_id,
            )

            assert persisted_run is not None
            assert persisted_run.status == "completed"
            assert persisted_run.records_received == 1
            assert persisted_run.records_succeeded == 1
            assert persisted_run.records_failed == 0

            assert persisted_payload is not None
            assert (
                persisted_payload.ingestion_run_id
                == run_id
            )

            assert persisted_state is not None
            assert persisted_state.cursor == "cursor-002"
            assert (
                persisted_state.last_success_at
                is not None
            )
            assert (
                persisted_state.last_attempt_at
                is not None
            )
            assert persisted_state.metadata_ == {
                "page": 2,
            }

    finally:
        _delete_test_data(
            owner_session_factory=owner_session_factory,
            source_id=source_id,
        )
def test_uow_rolls_back_complete_ingestion_flow() -> None:
    source_id = uuid4()
    source_code = f"UOW_SYNC_FAIL_{uuid4().hex[:18]}"
    external_record_id = f"RECORD-{uuid4()}"

    owner_session_factory = (
        _create_owner_session_factory()
    )

    ingestion_engine = create_ingestion_engine()
    ingestion_session_factory = (
        create_session_factory(
            ingestion_engine
        )
    )

    _create_source(
        owner_session_factory=owner_session_factory,
        source_id=source_id,
        source_code=source_code,
    )

    run_id: UUID | None = None
    payload_id: UUID | None = None

    attempted_at = datetime.now(UTC)

    try:
        unit_of_work = SqlAlchemyUnitOfWork(
            session_factory=ingestion_session_factory,
        )

        with pytest.raises(
            RuntimeError,
            match="forced complete flow failure",
        ):
            with unit_of_work:
                unit_of_work.sync_states.mark_attempt(
                    source_id=source_id,
                    attempted_at=attempted_at,
                )

                run_id = (
                    unit_of_work.ingestion_runs.create(
                        IngestionRunData(
                            source_id=source_id,
                            status="running",
                        )
                    )
                )

                payload_id = (
                    unit_of_work.raw_payloads.save(
                        RawPayloadData(
                            source_id=source_id,
                            ingestion_run_id=run_id,
                            external_record_id=(
                                external_record_id
                            ),
                            payload={
                                "id": external_record_id,
                            },
                            payload_hash="a" * 64,
                            http_status=200,
                        )
                    )
                )

                unit_of_work.sync_states.upsert(
                    SyncStateData(
                        source_id=source_id,
                        cursor="cursor-rollback",
                        last_attempt_at=attempted_at,
                        last_success_at=attempted_at,
                        metadata={
                            "page": 99,
                        },
                    )
                )

                raise RuntimeError(
                    "forced complete flow failure"
                )

        with ingestion_session_factory() as session:
            assert session.get(
                IngestionRunModel,
                run_id,
            ) is None

            assert session.get(
                SourcePayloadModel,
                payload_id,
            ) is None

            assert session.get(
                SyncStateModel,
                source_id,
            ) is None

    finally:
        _delete_test_data(
            owner_session_factory=owner_session_factory,
            source_id=source_id,
        )
