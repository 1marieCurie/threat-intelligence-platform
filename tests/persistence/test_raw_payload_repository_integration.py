from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from dotenv import load_dotenv

load_dotenv()

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
    IngestionRunPayloadModel,
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


def test_save_and_exists_with_real_postgresql() -> None:
    source_id = uuid4()
    ingestion_run_id = uuid4()
    external_record_id = f"TEST-{uuid4()}"
    payload_hash = "a" * 64
    source_code = f"TEST_RAW_{uuid4().hex}"

    owner_session_factory = (
        _create_owner_session_factory()
    )

    ingestion_engine = create_ingestion_engine()
    ingestion_session_factory = (
        create_session_factory(
            ingestion_engine
        )
    )

    with owner_session_factory() as owner_session:
        owner_session.execute(
            text(
                "SET ROLE threat_intel_owner"
            )
        )

        owner_session.add(
            SourceModel(
                id=source_id,
                code=source_code,
                name=(
                    "Raw repository integration test"
                ),
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

            repository = (
                SqlAlchemyRawPayloadRepository(
                    session=session,
                )
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
                external_record_id=(
                    external_record_id
                ),
                payload_hash=payload_hash,
            )

            session.rollback()

        with ingestion_session_factory() as session:
            assert (
                session.get(
                    SourcePayloadModel,
                    payload_id,
                )
                is None
            )

            assert (
                session.get(
                    IngestionRunModel,
                    ingestion_run_id,
                )
                is None
            )

    finally:
        with owner_session_factory() as session:
            session.execute(
                text(
                    "SET ROLE threat_intel_owner"
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

    payload_ids: list[UUID] = []

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
                    "Raw payload claiming "
                    "integration test"
                ),
            )
        )

        session.commit()

    try:
        with ingestion_session_factory() as session:
            session.add(
                IngestionRunModel(
                    id=ingestion_run_id,
                    source_id=source_id,
                    status="completed",
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

                observed_at = (
                    retrieved_at
                    + timedelta(
                        seconds=index
                    )
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
                        retrieved_at=observed_at,
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

                session.add(
                    IngestionRunPayloadModel(
                        ingestion_run_id=(
                            ingestion_run_id
                        ),
                        raw_payload_id=payload_id,
                        observed_at=observed_at,
                    )
                )

                payload_ids.append(
                    payload_id
                )

            session.commit()

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

            assert not repository.mark_processed(
                payload_id=payload_ids[2],
            )

            session.commit()

        with ingestion_session_factory() as session:
            statement = (
                select(
                    SourcePayloadModel
                )
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
                session.execute(
                    statement
                )
                .scalars()
                .all()
            )

            assert len(
                stored_payloads
            ) == 3

            assert [
                payload.processing_status
                for payload in stored_payloads
            ] == [
                "processed",
                "failed",
                "pending",
            ]

            assert (
                stored_payloads[0]
                .error_message
                is None
            )

            assert (
                stored_payloads[1]
                .error_message
                == "Normalization failed"
            )

            assert (
                stored_payloads[2]
                .error_message
                is None
            )

    finally:
        with owner_session_factory() as session:
            session.execute(
                text(
                    "SET ROLE threat_intel_owner"
                )
            )

            session.execute(
                delete(
                    SourcePayloadModel
                ).where(
                    SourcePayloadModel.source_id
                    == source_id
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


def test_claim_pending_skips_payloads_locked_by_another_worker(
) -> None:
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
                    "Raw payload concurrency "
                    "integration test"
                ),
            )
        )

        session.commit()

    try:
        with ingestion_session_factory() as session:
            session.add(
                IngestionRunModel(
                    id=ingestion_run_id,
                    source_id=source_id,
                    status="completed",
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

                observed_at = (
                    retrieved_at
                    + timedelta(
                        seconds=index
                    )
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
                        retrieved_at=observed_at,
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

                session.add(
                    IngestionRunPayloadModel(
                        ingestion_run_id=(
                            ingestion_run_id
                        ),
                        raw_payload_id=payload_id,
                        observed_at=observed_at,
                    )
                )

                payload_ids.append(
                    payload_id
                )

            session.commit()

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

                assert [
                    payload.id
                    for payload in second_claim
                ] == [
                    payload_ids[2]
                ]

                first_claim_ids = {
                    payload.id
                    for payload in first_claim
                }

                second_claim_ids = {
                    payload.id
                    for payload in second_claim
                }

                assert (
                    first_claim_ids
                    .isdisjoint(
                        second_claim_ids
                    )
                )

                second_session.commit()

            first_session.commit()

        with ingestion_session_factory() as session:
            statement = (
                select(
                    SourcePayloadModel
                )
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
                session.execute(
                    statement
                )
                .scalars()
                .all()
            )

            assert len(
                stored_payloads
            ) == 3

            assert all(
                payload.processing_status
                == "processing"
                for payload in stored_payloads
            )

    finally:
        with owner_session_factory() as session:
            session.execute(
                text(
                    "SET ROLE threat_intel_owner"
                )
            )

            session.execute(
                delete(
                    SourcePayloadModel
                ).where(
                    SourcePayloadModel.source_id
                    == source_id
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


def test_claim_pending_requires_completed_observation(
) -> None:
    source_id = uuid4()
    foreign_source_id = uuid4()

    running_run_id = uuid4()
    failed_run_id = uuid4()
    completed_run_id = uuid4()
    failed_creator_run_id = uuid4()
    completed_reobservation_run_id = uuid4()
    foreign_completed_run_id = uuid4()

    source_code = (
        f"TEST_RAW_STATUS_{uuid4().hex[:18]}"
    )

    foreign_source_code = (
        f"TEST_RAW_FOREIGN_{uuid4().hex[:17]}"
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

    payload_ids: dict[str, UUID] = {}

    with owner_session_factory() as session:
        session.execute(
            text(
                "SET ROLE threat_intel_owner"
            )
        )

        session.add_all(
            [
                SourceModel(
                    id=source_id,
                    code=source_code,
                    name=(
                        "Raw payload completed "
                        "observation test"
                    ),
                ),
                SourceModel(
                    id=foreign_source_id,
                    code=foreign_source_code,
                    name=(
                        "Foreign source completed "
                        "observation test"
                    ),
                ),
            ]
        )

        session.commit()

    try:
        with ingestion_session_factory() as session:
            session.add_all(
                [
                    IngestionRunModel(
                        id=running_run_id,
                        source_id=source_id,
                        status="running",
                    ),
                    IngestionRunModel(
                        id=failed_run_id,
                        source_id=source_id,
                        status="failed",
                    ),
                    IngestionRunModel(
                        id=completed_run_id,
                        source_id=source_id,
                        status="completed",
                    ),
                    IngestionRunModel(
                        id=failed_creator_run_id,
                        source_id=source_id,
                        status="failed",
                    ),
                    IngestionRunModel(
                        id=(
                            completed_reobservation_run_id
                        ),
                        source_id=source_id,
                        status="completed",
                    ),
                    IngestionRunModel(
                        id=foreign_completed_run_id,
                        source_id=foreign_source_id,
                        status="completed",
                    ),
                ]
            )

            session.flush()

            repository = (
                SqlAlchemyRawPayloadRepository(
                    session=session,
                )
            )

            payload_definitions = (
                (
                    "running_only",
                    running_run_id,
                ),
                (
                    "failed_only",
                    failed_run_id,
                ),
                (
                    "completed",
                    completed_run_id,
                ),
                (
                    "reobserved",
                    failed_creator_run_id,
                ),
                (
                    "foreign_completed",
                    failed_run_id,
                ),
            )

            for index, (
                payload_name,
                creator_run_id,
            ) in enumerate(
                payload_definitions
            ):
                payload_id = repository.save(
                    RawPayloadData(
                        source_id=source_id,
                        ingestion_run_id=(
                            creator_run_id
                        ),
                        external_record_id=(
                            f"{payload_name}-"
                            f"{uuid4()}"
                        ),
                        retrieved_at=(
                            retrieved_at
                            + timedelta(
                                seconds=index
                            )
                        ),
                        payload={
                            "name": payload_name,
                        },
                        payload_hash=(
                            f"{index + 100:064x}"
                        ),
                        http_status=200,
                    )
                )

                payload_ids[
                    payload_name
                ] = payload_id

            session.add_all(
                [
                    IngestionRunPayloadModel(
                        ingestion_run_id=(
                            running_run_id
                        ),
                        raw_payload_id=(
                            payload_ids[
                                "running_only"
                            ]
                        ),
                    ),
                    IngestionRunPayloadModel(
                        ingestion_run_id=(
                            failed_run_id
                        ),
                        raw_payload_id=(
                            payload_ids[
                                "failed_only"
                            ]
                        ),
                    ),
                    IngestionRunPayloadModel(
                        ingestion_run_id=(
                            completed_run_id
                        ),
                        raw_payload_id=(
                            payload_ids[
                                "completed"
                            ]
                        ),
                    ),
                    IngestionRunPayloadModel(
                        ingestion_run_id=(
                            failed_creator_run_id
                        ),
                        raw_payload_id=(
                            payload_ids[
                                "reobserved"
                            ]
                        ),
                    ),
                    IngestionRunPayloadModel(
                        ingestion_run_id=(
                            completed_reobservation_run_id
                        ),
                        raw_payload_id=(
                            payload_ids[
                                "reobserved"
                            ]
                        ),
                    ),
                    IngestionRunPayloadModel(
                        ingestion_run_id=(
                            foreign_completed_run_id
                        ),
                        raw_payload_id=(
                            payload_ids[
                                "foreign_completed"
                            ]
                        ),
                    ),
                ]
            )

            session.commit()

        with ingestion_session_factory() as session:
            repository = (
                SqlAlchemyRawPayloadRepository(
                    session=session,
                )
            )

            claimed_payloads = (
                repository.claim_pending(
                    source_id=source_id,
                    limit=10,
                )
            )

            assert [
                payload.id
                for payload in claimed_payloads
            ] == [
                payload_ids["completed"],
                payload_ids["reobserved"],
            ]

            session.commit()

        with ingestion_session_factory() as session:
            rows = (
                session.execute(
                    select(
                        SourcePayloadModel.id,
                        (
                            SourcePayloadModel
                            .processing_status
                        ),
                    )
                    .where(
                        SourcePayloadModel.id.in_(
                            tuple(
                                payload_ids.values()
                            )
                        )
                    )
                )
                .all()
            )

            statuses = {
                row.id: row.processing_status
                for row in rows
            }

            assert statuses[
                payload_ids["running_only"]
            ] == "pending"

            assert statuses[
                payload_ids["failed_only"]
            ] == "pending"

            assert statuses[
                payload_ids["completed"]
            ] == "processing"

            assert statuses[
                payload_ids["reobserved"]
            ] == "processing"

            assert statuses[
                payload_ids["foreign_completed"]
            ] == "pending"

    finally:
        with owner_session_factory() as session:
            session.execute(
                text(
                    "SET ROLE threat_intel_owner"
                )
            )

            session.execute(
                delete(
                    SourcePayloadModel
                ).where(
                    SourcePayloadModel.source_id
                    == source_id
                )
            )

            session.execute(
                delete(
                    IngestionRunModel
                ).where(
                    IngestionRunModel.source_id.in_(
                        (
                            source_id,
                            foreign_source_id,
                        )
                    )
                )
            )

            session.execute(
                delete(
                    SourceModel
                ).where(
                    SourceModel.id.in_(
                        (
                            source_id,
                            foreign_source_id,
                        )
                    )
                )
            )

            session.commit()