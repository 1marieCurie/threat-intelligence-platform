from __future__ import annotations

from dotenv import find_dotenv, load_dotenv

load_dotenv(
    dotenv_path=find_dotenv(usecwd=True),
    override=False,
)


import hashlib
import json
import os
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Self, cast
from uuid import UUID, uuid4

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

from application.ports.outbound.ingestion_connector import (
    FetchedRecord,
    FetchResult,
)
from application.ports.outbound.raw_payload_repository import (
    RawPayloadBatchSaveResult,
    RawPayloadData,
    RawPayloadRepository,
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
    IngestionRunPayloadModel,
    SourcePayloadModel,
)
from infrastructure.persistence.sqlalchemy import (
    SqlAlchemyUnitOfWork,
    create_ingestion_engine,
    create_session_factory,
)


pytestmark = pytest.mark.integration


PUBLIC_PHISHTANK_URL = (
    "https://data.phishtank.com/data/"
    "online-valid.json.bz2"
)


@dataclass(
    frozen=True,
    slots=True,
)
class DatabaseContext:
    source_id: UUID

    owner_session_factory: sessionmaker[
        Session
    ]

    ingestion_session_factory: sessionmaker[
        Session
    ]


@dataclass(
    slots=True,
)
class BatchFailureState:
    calls: int = 0


class StaticIngestionConnector:
    """
    Connecteur déterministe utilisé sans appel réseau.
    """

    def __init__(
        self,
        fetch_result: FetchResult,
    ) -> None:
        self._fetch_result = fetch_result

        self.calls: list[
            tuple[
                str | None,
                dict[str, object] | None,
            ]
        ] = []

    def fetch(
        self,
        *,
        cursor: str | None,
        state_metadata: (
            dict[str, object] | None
        ) = None,
    ) -> FetchResult:
        self.calls.append(
            (
                cursor,
                state_metadata,
            )
        )

        return self._fetch_result


class DeterministicPayloadHasher:
    """
    Hash JSON stable pour le test d'intégration.
    """

    def hash(
        self,
        payload: dict[str, object],
    ) -> str:
        serialized_payload = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

        return hashlib.sha256(
            serialized_payload.encode(
                "utf-8"
            )
        ).hexdigest()


class FailOnBatchRawPayloadRepository:
    """
    Décorateur provoquant une erreur avant l'écriture
    du lot configuré.
    """

    def __init__(
        self,
        *,
        delegate: RawPayloadRepository,
        state: BatchFailureState,
        fail_on_call: int,
    ) -> None:
        self._delegate = delegate
        self._state = state
        self._fail_on_call = fail_on_call

    def save_many_ignore_existing(
        self,
        payloads: Sequence[
            RawPayloadData
        ],
    ) -> RawPayloadBatchSaveResult:
        self._state.calls += 1

        if (
            self._state.calls
            == self._fail_on_call
        ):
            raise RuntimeError(
                "Simulated second batch failure"
            )

        return (
            self._delegate
            .save_many_ignore_existing(
                payloads
            )
        )


class FailOnSecondBatchUnitOfWork(
    SqlAlchemyUnitOfWork
):
    """
    Unit of Work réelle avec injection d'une défaillance
    avant la deuxième écriture raw.
    """

    def __init__(
        self,
        *,
        session_factory: sessionmaker[
            Session
        ],
    ) -> None:
        super().__init__(
            session_factory=session_factory,
        )

        self.failure_state = (
            BatchFailureState()
        )

    def __enter__(
        self,
    ) -> Self:
        super().__enter__()

        failing_repository = (
            FailOnBatchRawPayloadRepository(
                delegate=self.raw_payloads,
                state=self.failure_state,
                fail_on_call=2,
            )
        )

        self.raw_payloads = cast(
            RawPayloadRepository,
            failing_repository,
        )

        return self


def _create_owner_engine() -> Engine:
    database_url = os.environ.get(
        "MIGRATION_DATABASE_URL"
    )

    if not database_url:
        raise RuntimeError(
            "MIGRATION_DATABASE_URL is not defined"
        )

    return create_engine(
        database_url,
        pool_pre_ping=True,
    )


def _create_owner_session_factory(
    engine: Engine,
) -> sessionmaker[Session]:
    return sessionmaker(
        bind=engine,
        class_=Session,
        autoflush=False,
        expire_on_commit=False,
    )


def _build_fetch_result(
    *,
    records_count: int,
) -> FetchResult:
    fetched_at = datetime(
        2026,
        7,
        31,
        14,
        0,
        tzinfo=UTC,
    )

    records = tuple(
        FetchedRecord(
            external_record_id=str(
                1_000 + index
            ),
            payload={
                "phish_id": (
                    1_000 + index
                ),
                "url": (
                    "https://example.invalid/"
                    f"phish/{1_000 + index}"
                ),
                "verified": "yes",
                "online": "yes",
            },
            source_url=(
                PUBLIC_PHISHTANK_URL
            ),
            fetched_at=(
                fetched_at
                + timedelta(
                    seconds=index
                )
            ),
            http_status=200,
        )
        for index in range(
            records_count
        )
    )

    return FetchResult(
        records=records,
        next_cursor=None,
        metadata={
            "source": "phishtank",
            "snapshot_complete": True,
        },
        connector_version="1.0.0",
    )


def _delete_source_data(
    *,
    context: DatabaseContext,
) -> None:
    with (
        context.owner_session_factory()
        as session
    ):
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
                ).in_(
                    select(
                        IngestionRunModel.id
                    ).where(
                        (
                            IngestionRunModel
                            .source_id
                        )
                        == context.source_id
                    )
                )
            )
        )

        session.execute(
            delete(
                SourcePayloadModel
            ).where(
                SourcePayloadModel.source_id
                == context.source_id
            )
        )

        session.execute(
            delete(
                SyncStateModel
            ).where(
                SyncStateModel.source_id
                == context.source_id
            )
        )

        session.execute(
            delete(
                IngestionRunModel
            ).where(
                IngestionRunModel.source_id
                == context.source_id
            )
        )

        session.execute(
            delete(
                SourceModel
            ).where(
                SourceModel.id
                == context.source_id
            )
        )

        session.commit()


@pytest.fixture
def database_context(
) -> Iterator[DatabaseContext]:
    source_id = uuid4()

    owner_engine = (
        _create_owner_engine()
    )

    ingestion_engine = (
        create_ingestion_engine()
    )

    owner_session_factory = (
        _create_owner_session_factory(
            owner_engine
        )
    )

    ingestion_session_factory = (
        create_session_factory(
            ingestion_engine
        )
    )

    context = DatabaseContext(
        source_id=source_id,
        owner_session_factory=(
            owner_session_factory
        ),
        ingestion_session_factory=(
            ingestion_session_factory
        ),
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
                code=(
                    "TEST_INGEST_SERVICE_"
                    f"{uuid4().hex[:16]}"
                ),
                name=(
                    "Ingestion service "
                    "integration test"
                ),
                base_url=(
                    PUBLIC_PHISHTANK_URL
                ),
            )
        )

        session.commit()

    try:
        yield context

    finally:
        _delete_source_data(
            context=context
        )

        ingestion_engine.dispose()
        owner_engine.dispose()


def test_ingestion_service_persists_complete_snapshot(
    database_context: DatabaseContext,
) -> None:
    connector = StaticIngestionConnector(
        _build_fetch_result(
            records_count=3
        )
    )

    unit_of_work = SqlAlchemyUnitOfWork(
        session_factory=(
            database_context
            .ingestion_session_factory
        )
    )

    service = IngestionService(
        unit_of_work=unit_of_work,
        connector=connector,
        payload_hasher=(
            DeterministicPayloadHasher()
        ),
        batch_size=2,
    )

    result = service.ingest(
        source_id=(
            database_context.source_id
        )
    )

    assert result.status == "completed"
    assert result.records_received == 3
    assert result.records_persisted == 3
    assert result.records_skipped == 0
    assert result.pagination_complete is True

    assert connector.calls == [
        (
            None,
            None,
        )
    ]

    with (
        database_context
        .ingestion_session_factory()
        as session
    ):
        ingestion_run = (
            session.execute(
                select(
                    IngestionRunModel
                ).where(
                    (
                        IngestionRunModel
                        .source_id
                    )
                    == database_context.source_id
                )
            )
            .scalar_one()
        )

        assert (
            ingestion_run.id
            == result.run_id
        )

        assert (
            ingestion_run.status
            == "completed"
        )

        assert (
            ingestion_run.finished_at
            is not None
        )

        assert (
            ingestion_run.records_received
            == 3
        )

        assert (
            ingestion_run.records_succeeded
            == 3
        )

        assert (
            ingestion_run.records_failed
            == 0
        )

        assert (
            ingestion_run.error_summary
            is None
        )

        assert (
            ingestion_run.connector_version
            == "1.0.0"
        )

        assert (
            ingestion_run.metadata_[
                "snapshot_complete"
            ]
            is True
        )

        assert (
            ingestion_run.metadata_[
                "records_persisted"
            ]
            == 3
        )

        assert (
            ingestion_run.metadata_[
                "records_skipped"
            ]
            == 0
        )

        assert (
            ingestion_run.metadata_[
                "batch_size"
            ]
            == 2
        )

        stored_payloads = tuple(
            session.execute(
                select(
                    SourcePayloadModel
                )
                .where(
                    (
                        SourcePayloadModel
                        .source_id
                    )
                    == database_context.source_id
                )
                .order_by(
                    (
                        SourcePayloadModel
                        .external_record_id
                    )
                )
            )
            .scalars()
            .all()
        )

        assert len(
            stored_payloads
        ) == 3

        assert {
            payload.external_record_id
            for payload in stored_payloads
        } == {
            "1000",
            "1001",
            "1002",
        }

        assert all(
            payload.ingestion_run_id
            == result.run_id
            for payload in stored_payloads
        )

        assert all(
            payload.request_url
            == PUBLIC_PHISHTANK_URL
            for payload in stored_payloads
        )

        assert all(
            payload.processing_status
            == "pending"
            for payload in stored_payloads
        )

        stored_links = tuple(
            session.execute(
                select(
                    IngestionRunPayloadModel
                ).where(
                    (
                        IngestionRunPayloadModel
                        .ingestion_run_id
                    )
                    == result.run_id
                )
            )
            .scalars()
            .all()
        )

        assert len(
            stored_links
        ) == 3

        assert {
            link.raw_payload_id
            for link in stored_links
        } == {
            payload.id
            for payload in stored_payloads
        }

        sync_state = session.get(
            SyncStateModel,
            database_context.source_id,
        )

        assert sync_state is not None
        assert sync_state.cursor is None

        assert (
            sync_state.last_attempt_at
            is not None
        )

        assert (
            sync_state.last_success_at
            is not None
        )

        assert (
            sync_state.metadata_[
                "snapshot_complete"
            ]
            is True
        )

        assert (
            sync_state.metadata_[
                "records_persisted"
            ]
            == 3
        )


def test_ingestion_service_preserves_first_batch_when_second_fails(
    database_context: DatabaseContext,
) -> None:
    connector = StaticIngestionConnector(
        _build_fetch_result(
            records_count=3
        )
    )

    unit_of_work = (
        FailOnSecondBatchUnitOfWork(
            session_factory=(
                database_context
                .ingestion_session_factory
            )
        )
    )

    service = IngestionService(
        unit_of_work=unit_of_work,
        connector=connector,
        payload_hasher=(
            DeterministicPayloadHasher()
        ),
        batch_size=2,
    )

    with pytest.raises(
        RuntimeError,
        match=(
            "Simulated second batch failure"
        ),
    ):
        service.ingest(
            source_id=(
                database_context.source_id
            )
        )

    assert (
        unit_of_work
        .failure_state
        .calls
        == 2
    )

    with (
        database_context
        .ingestion_session_factory()
        as session
    ):
        ingestion_run = (
            session.execute(
                select(
                    IngestionRunModel
                ).where(
                    (
                        IngestionRunModel
                        .source_id
                    )
                    == database_context.source_id
                )
            )
            .scalar_one()
        )

        assert (
            ingestion_run.status
            == "failed"
        )

        assert (
            ingestion_run.finished_at
            is not None
        )

        assert (
            ingestion_run.error_summary
            == (
                "RuntimeError: Simulated "
                "second batch failure"
            )
        )

        stored_payloads = tuple(
            session.execute(
                select(
                    SourcePayloadModel
                )
                .where(
                    (
                        SourcePayloadModel
                        .source_id
                    )
                    == database_context.source_id
                )
                .order_by(
                    (
                        SourcePayloadModel
                        .external_record_id
                    )
                )
            )
            .scalars()
            .all()
        )

        # Le premier lot a été validé avant la défaillance.
        assert len(
            stored_payloads
        ) == 2

        assert {
            payload.external_record_id
            for payload in stored_payloads
        } == {
            "1000",
            "1001",
        }

        # Le troisième élément appartenait au second lot.
        assert all(
            payload.external_record_id
            != "1002"
            for payload in stored_payloads
        )

        stored_links = tuple(
            session.execute(
                select(
                    IngestionRunPayloadModel
                ).where(
                    (
                        IngestionRunPayloadModel
                        .ingestion_run_id
                    )
                    == ingestion_run.id
                )
            )
            .scalars()
            .all()
        )

        assert len(
            stored_links
        ) == 2

        assert {
            link.raw_payload_id
            for link in stored_links
        } == {
            payload.id
            for payload in stored_payloads
        }

        # Aucun sync state ne doit annoncer un snapshot réussi.
        sync_state = session.get(
            SyncStateModel,
            database_context.source_id,
        )

        assert sync_state is None
        
        assert (
        ingestion_run.records_received
        == 3
        )

        assert (
            ingestion_run.records_succeeded
            == 2
        )

        assert (
            ingestion_run.records_failed
            == 1
        )