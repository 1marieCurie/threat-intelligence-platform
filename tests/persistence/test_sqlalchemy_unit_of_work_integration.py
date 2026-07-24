from __future__ import annotations

import os
from uuid import UUID, uuid4

import pytest
from sqlalchemy import create_engine, delete, select, text
from sqlalchemy.orm import Session, sessionmaker

from application.ports.outbound.raw_payload_repository import (
    RawPayloadData,
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


def _create_owner_session_factory() -> sessionmaker[Session]:
    database_url = os.environ.get("MIGRATION_DATABASE_URL")

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


def _create_source_and_run(
    *,
    owner_session_factory: sessionmaker[Session],
    ingestion_session_factory: sessionmaker[Session],
    source_id: UUID,
    ingestion_run_id: UUID,
    source_code: str,
) -> None:
    with owner_session_factory() as owner_session:
        owner_session.execute(
            text("SET ROLE threat_intel_owner")
        )

        owner_session.add(
            SourceModel(
                id=source_id,
                code=source_code,
                name="Unit of Work integration test",
            )
        )

        owner_session.commit()

    with ingestion_session_factory() as ingestion_session:
        ingestion_session.add(
            IngestionRunModel(
                id=ingestion_run_id,
                source_id=source_id,
                status="running",
            )
        )

        ingestion_session.commit()


def _delete_source(
    *,
    owner_session_factory: sessionmaker[Session],
    source_id: UUID,
) -> None:
    with owner_session_factory() as owner_session:
        owner_session.execute(
            text("SET ROLE threat_intel_owner")
        )

        run_ids = select(IngestionRunModel.id).where(
            IngestionRunModel.source_id == source_id
        )

        owner_session.execute(
            delete(SourcePayloadModel).where(
                SourcePayloadModel.ingestion_run_id.in_(
                    run_ids
                )
            )
        )

        owner_session.execute(
            delete(IngestionRunModel).where(
                IngestionRunModel.source_id == source_id
            )
        )

        owner_session.execute(
            delete(SourceModel).where(
                SourceModel.id == source_id
            )
        )

        owner_session.commit()
        
        
def test_commit_persists_payload() -> None:
    source_id = uuid4()
    ingestion_run_id = uuid4()
    source_code = f"UOW_COMMIT_{uuid4().hex[:20]}"
    external_record_id = f"RECORD-{uuid4()}"

    owner_session_factory = _create_owner_session_factory()

    ingestion_engine = create_ingestion_engine()
    ingestion_session_factory = create_session_factory(
        ingestion_engine
    )

    _create_source_and_run(
        owner_session_factory=owner_session_factory,
        ingestion_session_factory=ingestion_session_factory,
        source_id=source_id,
        ingestion_run_id=ingestion_run_id,
        source_code=source_code,
    )

    payload_id: UUID | None = None

    try:
        unit_of_work = SqlAlchemyUnitOfWork(
            session_factory=ingestion_session_factory,
        )

        with unit_of_work:
            payload_id = unit_of_work.raw_payloads.save(
                RawPayloadData(
                    source_id=source_id,
                    ingestion_run_id=ingestion_run_id,
                    external_record_id=external_record_id,
                    payload={
                        "id": external_record_id,
                    },
                    payload_hash="a" * 64,
                    http_status=200,
                )
            )

            unit_of_work.commit()

        with ingestion_session_factory() as session:
            persisted_payload = session.get(
                SourcePayloadModel,
                payload_id,
            )

            assert persisted_payload is not None
            assert (
                persisted_payload.external_record_id
                == external_record_id
            )

    finally:
        _delete_source(
            owner_session_factory=owner_session_factory,
            source_id=source_id,
        )


def test_missing_commit_rolls_back_payload() -> None:
    source_id = uuid4()
    ingestion_run_id = uuid4()
    source_code = f"UOW_ROLLBACK_{uuid4().hex[:18]}"
    external_record_id = f"RECORD-{uuid4()}"

    owner_session_factory = _create_owner_session_factory()

    ingestion_engine = create_ingestion_engine()
    ingestion_session_factory = create_session_factory(
        ingestion_engine
    )

    _create_source_and_run(
        owner_session_factory=owner_session_factory,
        ingestion_session_factory=ingestion_session_factory,
        source_id=source_id,
        ingestion_run_id=ingestion_run_id,
        source_code=source_code,
    )

    payload_id: UUID | None = None

    try:
        unit_of_work = SqlAlchemyUnitOfWork(
            session_factory=ingestion_session_factory,
        )

        with unit_of_work:
            payload_id = unit_of_work.raw_payloads.save(
                RawPayloadData(
                    source_id=source_id,
                    ingestion_run_id=ingestion_run_id,
                    external_record_id=external_record_id,
                    payload={
                        "id": external_record_id,
                    },
                    payload_hash="b" * 64,
                    http_status=200,
                )
            )

        with ingestion_session_factory() as session:
            persisted_payload = session.get(
                SourcePayloadModel,
                payload_id,
            )

            assert persisted_payload is None

    finally:
        _delete_source(
            owner_session_factory=owner_session_factory,
            source_id=source_id,
        )


def test_exception_rolls_back_payload() -> None:
    source_id = uuid4()
    ingestion_run_id = uuid4()
    source_code = f"UOW_EXCEPTION_{uuid4().hex[:17]}"
    external_record_id = f"RECORD-{uuid4()}"

    owner_session_factory = _create_owner_session_factory()

    ingestion_engine = create_ingestion_engine()
    ingestion_session_factory = create_session_factory(
        ingestion_engine
    )

    _create_source_and_run(
        owner_session_factory=owner_session_factory,
        ingestion_session_factory=ingestion_session_factory,
        source_id=source_id,
        ingestion_run_id=ingestion_run_id,
        source_code=source_code,
    )

    payload_id: UUID | None = None

    try:
        unit_of_work = SqlAlchemyUnitOfWork(
            session_factory=ingestion_session_factory,
        )

        with pytest.raises(
            RuntimeError,
            match="forced failure",
        ):
            with unit_of_work:
                payload_id = unit_of_work.raw_payloads.save(
                    RawPayloadData(
                        source_id=source_id,
                        ingestion_run_id=ingestion_run_id,
                        external_record_id=external_record_id,
                        payload={
                            "id": external_record_id,
                        },
                        payload_hash="c" * 64,
                        http_status=200,
                    )
                )

                raise RuntimeError("forced failure")

        with ingestion_session_factory() as session:
            persisted_payload = session.get(
                SourcePayloadModel,
                payload_id,
            )

            assert persisted_payload is None

    finally:
        _delete_source(
            owner_session_factory=owner_session_factory,
            source_id=source_id,
        )