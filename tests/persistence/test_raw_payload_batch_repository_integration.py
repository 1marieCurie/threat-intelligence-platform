from __future__ import annotations

from dotenv import find_dotenv, load_dotenv

load_dotenv(
    dotenv_path=find_dotenv(usecwd=True),
    override=False,
)


import os
from uuid import uuid4

import pytest
from sqlalchemy import (
    create_engine,
    delete,
    func,
    select,
    text,
)
from sqlalchemy.orm import (
    Session,
    sessionmaker,
)

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


def _create_owner_session_factory(
) -> sessionmaker[Session]:
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


def test_batch_insert_resolves_new_and_existing_payloads(
) -> None:
    source_id = uuid4()
    first_run_id = uuid4()
    second_run_id = uuid4()

    source_code = (
        f"TEST_RAW_BATCH_{uuid4().hex[:16]}"
    )

    owner_session_factory = (
        _create_owner_session_factory()
    )

    ingestion_engine = (
        create_ingestion_engine()
    )

    ingestion_session_factory = (
        create_session_factory(
            ingestion_engine
        )
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
                    "Raw batch repository "
                    "integration test"
                ),
            )
        )

        session.commit()

    try:
        with ingestion_session_factory() as session:
            session.add_all(
                [
                    IngestionRunModel(
                        id=first_run_id,
                        source_id=source_id,
                        status="running",
                    ),
                    IngestionRunModel(
                        id=second_run_id,
                        source_id=source_id,
                        status="running",
                    ),
                ]
            )

            session.commit()

        first_payloads = [
            RawPayloadData(
                source_id=source_id,
                ingestion_run_id=(
                    first_run_id
                ),
                external_record_id="1001",
                payload={
                    "phish_id": 1001,
                    "url": (
                        "https://one.example.invalid"
                    ),
                },
                payload_hash="a" * 64,
            ),
            RawPayloadData(
                source_id=source_id,
                ingestion_run_id=(
                    first_run_id
                ),
                external_record_id="1002",
                payload={
                    "phish_id": 1002,
                    "url": (
                        "https://two.example.invalid"
                    ),
                },
                payload_hash="b" * 64,
            ),
        ]

        with ingestion_session_factory() as session:
            repository = (
                SqlAlchemyRawPayloadRepository(
                    session=session
                )
            )

            first_result = (
                repository
                .save_many_ignore_existing(
                    first_payloads
                )
            )

            session.commit()

        assert (
            first_result.submitted_count
            == 2
        )

        assert (
            first_result.unique_count
            == 2
        )

        assert (
            first_result.inserted_count
            == 2
        )

        assert (
            first_result.existing_count
            == 0
        )

        first_ids = {
            (
                reference.identity
                .external_record_id,
                reference.identity
                .payload_hash,
            ): reference.payload_id
            for reference
            in first_result.references
        }

        second_payloads = [
            RawPayloadData(
                source_id=source_id,
                ingestion_run_id=(
                    second_run_id
                ),
                external_record_id="1001",
                payload={
                    "phish_id": 1001,
                    "url": (
                        "https://one.example.invalid"
                    ),
                },
                payload_hash="a" * 64,
            ),
            RawPayloadData(
                source_id=source_id,
                ingestion_run_id=(
                    second_run_id
                ),
                external_record_id="1002",
                payload={
                    "phish_id": 1002,
                    "url": (
                        "https://two.example.invalid"
                    ),
                },
                payload_hash="b" * 64,
            ),
            RawPayloadData(
                source_id=source_id,
                ingestion_run_id=(
                    second_run_id
                ),
                external_record_id="1001",
                payload={
                    "phish_id": 1001,
                    "url": (
                        "https://changed.example.invalid"
                    ),
                },
                payload_hash="c" * 64,
            ),
        ]

        with ingestion_session_factory() as session:
            repository = (
                SqlAlchemyRawPayloadRepository(
                    session=session
                )
            )

            second_result = (
                repository
                .save_many_ignore_existing(
                    second_payloads
                )
            )

            session.commit()

        assert (
            second_result.submitted_count
            == 3
        )

        assert (
            second_result.unique_count
            == 3
        )

        assert (
            second_result.inserted_count
            == 1
        )

        assert (
            second_result.existing_count
            == 2
        )

        assert (
            second_result.skipped_count
            == 2
        )

        second_ids = {
            (
                reference.identity
                .external_record_id,
                reference.identity
                .payload_hash,
            ): reference.payload_id
            for reference
            in second_result.references
        }

        assert (
            second_ids[
                (
                    "1001",
                    "a" * 64,
                )
            ]
            == first_ids[
                (
                    "1001",
                    "a" * 64,
                )
            ]
        )

        assert (
            second_ids[
                (
                    "1002",
                    "b" * 64,
                )
            ]
            == first_ids[
                (
                    "1002",
                    "b" * 64,
                )
            ]
        )

        with ingestion_session_factory() as session:
            stored_count = (
                session.execute(
                    select(
                        func.count()
                    )
                    .select_from(
                        SourcePayloadModel
                    )
                    .where(
                        SourcePayloadModel.source_id
                        == source_id
                    )
                )
                .scalar_one()
            )

            assert stored_count == 3

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