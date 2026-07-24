from __future__ import annotations

import os
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, delete, text
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
    create_ingestion_engine,
    create_session_factory,
)
from infrastructure.persistence.sqlalchemy.repositories.raw_payload_repository import (
    SqlAlchemyRawPayloadRepository,
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


def test_save_and_exists_with_real_postgresql() -> None:
    source_id = uuid4()
    ingestion_run_id = uuid4()
    external_record_id = f"TEST-{uuid4()}"
    payload_hash = "a" * 64
    source_code = f"TEST_RAW_{uuid4().hex}"

    owner_session_factory = _create_owner_session_factory()

    ingestion_engine = create_ingestion_engine()
    ingestion_session_factory = create_session_factory(
        ingestion_engine
    )

    # Le compte migrator prend temporairement le rôle owner
    # pour créer la donnée de référence ops.source.
    with owner_session_factory() as owner_session:
        owner_session.execute(
            text("SET ROLE threat_intel_owner")
        )

        owner_session.add(
            SourceModel(
                id=source_id,
                code=source_code,
                name="Raw repository integration test",
            )
        )

        owner_session.commit()

    try:
        with ingestion_session_factory() as session:
            session.add(
                IngestionRunModel(
                    id=ingestion_run_id,
                    source_id=source_id,
                    status="running",
                )
            )
            session.flush()

            repository = SqlAlchemyRawPayloadRepository(
                session=session,
            )

            payload_id = repository.save(
                RawPayloadData(
                    source_id=source_id,
                    ingestion_run_id=ingestion_run_id,
                    external_record_id=external_record_id,
                    payload={
                        "id": external_record_id,
                    },
                    payload_hash=payload_hash,
                    http_status=200,
                )
            )

            assert payload_id is not None

            assert repository.exists_by_identity(
                source_id=source_id,
                external_record_id=external_record_id,
                payload_hash=payload_hash,
            )

            session.rollback()

        # Le rollback doit supprimer le run et le payload.
        with ingestion_session_factory() as verification_session:
            assert (
                verification_session.get(
                    SourcePayloadModel,
                    payload_id,
                )
                is None
            )

            assert (
                verification_session.get(
                    IngestionRunModel,
                    ingestion_run_id,
                )
                is None
            )

    finally:
        # Nettoyage de la source créée pour le test.
        with owner_session_factory() as owner_session:
            owner_session.execute(
                text("SET ROLE threat_intel_owner")
            )

            owner_session.execute(
                delete(SourceModel).where(
                    SourceModel.id == source_id
                )
            )

            owner_session.commit()