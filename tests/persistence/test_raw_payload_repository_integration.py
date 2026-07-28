from __future__ import annotations
from dotenv import load_dotenv

import os
from uuid import UUID, uuid4
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import (
    create_engine,
    delete,
    select,
    text,
)
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

load_dotenv()

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


def test_claim_and_transition_with_real_postgresql() -> None:
    source_id = uuid4()
    ingestion_run_id = uuid4()
    source_code = (
        f"TEST_RAW_CLAIM_{uuid4().hex}"
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

    retrieved_at = (
        datetime.now(UTC)
        - timedelta(minutes=10)
    )

    payload_ids = []

    with owner_session_factory() as owner_session:
        owner_session.execute(
            text("SET ROLE threat_intel_owner")
        )

        owner_session.add(
            SourceModel(
                id=source_id,
                code=source_code,
                name=(
                    "Raw payload claiming integration test"
                ),
            )
        )

        owner_session.commit()

    try:
        # ---------------------------------------------------------
        # Arrange: persister trois payloads pending
        # ---------------------------------------------------------
        with ingestion_session_factory() as session:
            session.add(
                IngestionRunModel(
                    id=ingestion_run_id,
                    source_id=source_id,
                    status="running",
                )
            )

            session.flush()

            repository = (
                SqlAlchemyRawPayloadRepository(
                    session=session,
                )
            )

            for index in range(3):
                external_record_id = (
                    f"TEST-{uuid4()}"
                )

                payload_id = repository.save(
                    RawPayloadData(
                        source_id=source_id,
                        ingestion_run_id=(
                            ingestion_run_id
                        ),
                        external_record_id=(
                            external_record_id
                        ),
                        retrieved_at=(
                            retrieved_at
                            + timedelta(
                                seconds=index
                            )
                        ),
                        payload={
                            "id": external_record_id,
                            "position": index,
                        },
                        payload_hash=(
                            f"{index + 1:064x}"
                        ),
                        http_status=200,
                    )
                )

                payload_ids.append(payload_id)

            session.commit()

        # ---------------------------------------------------------
        # Act: réserver les deux plus anciens payloads
        # ---------------------------------------------------------
        with ingestion_session_factory() as session:
            repository = (
                SqlAlchemyRawPayloadRepository(
                    session=session,
                )
            )

            claimed_payloads = (
                repository.claim_pending(
                    source_id=source_id,
                    limit=2,
                )
            )

            assert [
                payload.id
                for payload in claimed_payloads
            ] == payload_ids[:2]

            assert all(
                payload.processing_status
                == "processing"
                for payload in claimed_payloads
            )

            session.commit()

        # ---------------------------------------------------------
        # Act: finaliser un succès et un échec
        # ---------------------------------------------------------
        with ingestion_session_factory() as session:
            repository = (
                SqlAlchemyRawPayloadRepository(
                    session=session,
                )
            )

            assert repository.mark_processed(
                payload_id=payload_ids[0],
            )

            assert repository.mark_failed(
                payload_id=payload_ids[1],
                error_message=(
                    "Normalization failed"
                ),
            )

            # Le troisième payload est encore pending.
            # La transition pending -> processed est interdite.
            assert not repository.mark_processed(
                payload_id=payload_ids[2],
            )

            session.commit()

        # ---------------------------------------------------------
        # Assert: vérifier l'état réellement persisté
        # ---------------------------------------------------------
        with ingestion_session_factory() as session:
            statement = (
                select(SourcePayloadModel)
                .where(
                    SourcePayloadModel.source_id
                    == source_id
                )
                .order_by(
                    SourcePayloadModel
                    .retrieved_at
                    .asc(),
                    SourcePayloadModel.id.asc(),
                )
            )

            stored_payloads = list(
                session.execute(statement)
                .scalars()
                .all()
            )

            assert len(stored_payloads) == 3

            assert [
                payload.processing_status
                for payload in stored_payloads
            ] == [
                "processed",
                "failed",
                "pending",
            ]

            assert (
                stored_payloads[0].error_message
                is None
            )

            assert (
                stored_payloads[1].error_message
                == "Normalization failed"
            )

            assert (
                stored_payloads[2].error_message
                is None
            )

    finally:
        # Nettoyage dans l'ordre des clés étrangères :
        # payloads -> runs -> source.
        with owner_session_factory() as owner_session:
            owner_session.execute(
                text("SET ROLE threat_intel_owner")
            )

            owner_session.execute(
                delete(SourcePayloadModel).where(
                    SourcePayloadModel.source_id
                    == source_id
                )
            )

            owner_session.execute(
                delete(IngestionRunModel).where(
                    IngestionRunModel.source_id
                    == source_id
                )
            )

            owner_session.execute(
                delete(SourceModel).where(
                    SourceModel.id == source_id
                )
            )

            owner_session.commit()
            
            
def test_claim_pending_skips_payloads_locked_by_another_worker() -> None:
    source_id = uuid4()
    ingestion_run_id = uuid4()
    source_code = (
        f"TEST_RAW_CONC_{uuid4().hex[:20]}"
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

    retrieved_at = (
        datetime.now(UTC)
        - timedelta(minutes=10)
    )

    payload_ids: list[UUID] = []

    with owner_session_factory() as owner_session:
        owner_session.execute(
            text("SET ROLE threat_intel_owner")
        )

        owner_session.add(
            SourceModel(
                id=source_id,
                code=source_code,
                name=(
                    "Raw payload concurrency integration test"
                ),
            )
        )

        owner_session.commit()

    try:
        # ---------------------------------------------------------
        # Arrange : créer trois payloads en attente
        # ---------------------------------------------------------
        with ingestion_session_factory() as session:
            session.add(
                IngestionRunModel(
                    id=ingestion_run_id,
                    source_id=source_id,
                    status="running",
                )
            )

            session.flush()

            repository = (
                SqlAlchemyRawPayloadRepository(
                    session=session,
                )
            )

            for index in range(3):
                external_record_id = (
                    f"CONCURRENT-{uuid4()}"
                )

                payload_id = repository.save(
                    RawPayloadData(
                        source_id=source_id,
                        ingestion_run_id=(
                            ingestion_run_id
                        ),
                        external_record_id=(
                            external_record_id
                        ),
                        retrieved_at=(
                            retrieved_at
                            + timedelta(seconds=index)
                        ),
                        payload={
                            "id": external_record_id,
                            "position": index,
                        },
                        payload_hash=(
                            f"{index + 10:064x}"
                        ),
                        http_status=200,
                    )
                )

                payload_ids.append(payload_id)

            session.commit()

        # ---------------------------------------------------------
        # Act : deux workers utilisent deux transactions distinctes
        # ---------------------------------------------------------
        with ingestion_session_factory() as first_session:
            first_repository = (
                SqlAlchemyRawPayloadRepository(
                    session=first_session,
                )
            )

            first_claim = (
                first_repository.claim_pending(
                    source_id=source_id,
                    limit=2,
                )
            )

            # Ne pas commiter : le premier worker conserve
            # les verrous PostgreSQL sur les deux lignes.
            assert [
                payload.id
                for payload in first_claim
            ] == payload_ids[:2]

            with ingestion_session_factory() as second_session:
                second_repository = (
                    SqlAlchemyRawPayloadRepository(
                        session=second_session,
                    )
                )

                second_claim = (
                    second_repository.claim_pending(
                        source_id=source_id,
                        limit=2,
                    )
                )

                # SKIP LOCKED ignore les deux lignes réservées
                # par le premier worker.
                assert [
                    payload.id
                    for payload in second_claim
                ] == [payload_ids[2]]

                first_claim_ids = {
                    payload.id
                    for payload in first_claim
                }

                second_claim_ids = {
                    payload.id
                    for payload in second_claim
                }

                assert first_claim_ids.isdisjoint(
                    second_claim_ids
                )

                second_session.commit()

            first_session.commit()

        # ---------------------------------------------------------
        # Assert : les trois lignes ont été réservées une seule fois
        # ---------------------------------------------------------
        with ingestion_session_factory() as session:
            statement = (
                select(SourcePayloadModel)
                .where(
                    SourcePayloadModel.source_id
                    == source_id
                )
                .order_by(
                    SourcePayloadModel
                    .retrieved_at
                    .asc(),
                    SourcePayloadModel.id.asc(),
                )
            )

            stored_payloads = list(
                session.execute(statement)
                .scalars()
                .all()
            )

            assert len(stored_payloads) == 3

            assert all(
                payload.processing_status
                == "processing"
                for payload in stored_payloads
            )

    finally:
        with owner_session_factory() as owner_session:
            owner_session.execute(
                text("SET ROLE threat_intel_owner")
            )

            owner_session.execute(
                delete(SourcePayloadModel).where(
                    SourcePayloadModel.source_id
                    == source_id
                )
            )

            owner_session.execute(
                delete(IngestionRunModel).where(
                    IngestionRunModel.source_id
                    == source_id
                )
            )

            owner_session.execute(
                delete(SourceModel).where(
                    SourceModel.id == source_id
                )
            )

            owner_session.commit()