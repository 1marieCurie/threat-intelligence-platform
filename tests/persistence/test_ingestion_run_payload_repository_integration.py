from __future__ import annotations

import os
from pathlib import Path
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
    func,
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
from infrastructure.persistence.sqlalchemy.repositories.ingestion_run_payload_repository import (
    SqlAlchemyIngestionRunPayloadRepository,
)


pytestmark = pytest.mark.integration


def _create_owner_resources() -> tuple[
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

    return engine, session_factory


def _create_source(
    *,
    owner_session_factory: sessionmaker[Session],
    source_id: UUID,
    source_code: str,
) -> None:
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
                    "Run payload repository "
                    "integration test"
                ),
            )
        )

        session.commit()


def _delete_test_data(
    *,
    owner_session_factory: sessionmaker[Session],
    source_id: UUID,
    run_id: UUID,
) -> None:
    with owner_session_factory() as session:
        session.execute(
            text(
                "SET ROLE threat_intel_owner"
            )
        )

        session.execute(
            delete(
                IngestionRunPayloadModel
            ).where(
                (
                    IngestionRunPayloadModel
                    .ingestion_run_id
                )
                == run_id
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


def test_links_payloads_to_run_without_duplicates(
) -> None:
    source_id = uuid4()
    run_id = uuid4()

    first_payload_id = uuid4()
    second_payload_id = uuid4()

    source_code = (
        "TEST_RUN_PAYLOAD_"
        f"{uuid4().hex[:16]}"
    )

    owner_engine, owner_session_factory = (
        _create_owner_resources()
    )

    ingestion_engine: Engine | None = None

    try:
        ingestion_engine = (
            create_ingestion_engine()
        )

        ingestion_session_factory = (
            create_session_factory(
                ingestion_engine
            )
        )

        _create_source(
            owner_session_factory=(
                owner_session_factory
            ),
            source_id=source_id,
            source_code=source_code,
        )

        with (
            ingestion_session_factory()
            as session
        ):
            session.add(
                IngestionRunModel(
                    id=run_id,
                    source_id=source_id,
                    status="running",
                )
            )

            session.add_all(
                [
                    SourcePayloadModel(
                        id=first_payload_id,
                        source_id=source_id,
                        ingestion_run_id=run_id,
                        external_record_id="1001",
                        payload={
                            "phish_id": 1001,
                        },
                        payload_hash="a" * 64,
                    ),
                    SourcePayloadModel(
                        id=second_payload_id,
                        source_id=source_id,
                        ingestion_run_id=run_id,
                        external_record_id="1002",
                        payload={
                            "phish_id": 1002,
                        },
                        payload_hash="b" * 64,
                    ),
                ]
            )

            session.commit()

        links = [
            IngestionRunPayloadLink(
                ingestion_run_id=run_id,
                raw_payload_id=(
                    first_payload_id
                ),
            ),
            IngestionRunPayloadLink(
                ingestion_run_id=run_id,
                raw_payload_id=(
                    second_payload_id
                ),
            ),
            IngestionRunPayloadLink(
                ingestion_run_id=run_id,
                raw_payload_id=(
                    first_payload_id
                ),
            ),
        ]

        with (
            ingestion_session_factory()
            as session
        ):
            repository = (
                SqlAlchemyIngestionRunPayloadRepository(
                    session=session
                )
            )

            first_result = (
                repository
                .link_many_ignore_existing(
                    links
                )
            )

            session.commit()

        assert (
            first_result.submitted_count
            == 3
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
            first_result.duplicate_count
            == 1
        )

        with (
            ingestion_session_factory()
            as session
        ):
            repository = (
                SqlAlchemyIngestionRunPayloadRepository(
                    session=session
                )
            )

            second_result = (
                repository
                .link_many_ignore_existing(
                    links[:2]
                )
            )

            session.commit()

        assert (
            second_result.submitted_count
            == 2
        )

        assert (
            second_result.unique_count
            == 2
        )

        assert (
            second_result.inserted_count
            == 0
        )

        assert (
            second_result.existing_count
            == 2
        )

        with (
            ingestion_session_factory()
            as session
        ):
            stored_count = (
                session.execute(
                    select(
                        func.count()
                    )
                    .select_from(
                        IngestionRunPayloadModel
                    )
                    .where(
                        (
                            IngestionRunPayloadModel
                            .ingestion_run_id
                        )
                        == run_id
                    )
                )
                .scalar_one()
            )

        assert stored_count == 2

    finally:
        try:
            _delete_test_data(
                owner_session_factory=(
                    owner_session_factory
                ),
                source_id=source_id,
                run_id=run_id,
            )
        finally:
            if ingestion_engine is not None:
                ingestion_engine.dispose()

            owner_engine.dispose()