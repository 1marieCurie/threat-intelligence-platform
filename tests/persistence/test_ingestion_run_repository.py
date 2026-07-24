from datetime import UTC, datetime
from unittest.mock import Mock
from uuid import uuid4

from sqlalchemy.orm import Session

from application.ports.outbound.ingestion_run_repository import (
    IngestionRunData,
)
from infrastructure.persistence.sqlalchemy.repositories.ingestion_run_repository import (
    SqlAlchemyIngestionRunRepository,
)


def test_create_adds_run_and_flushes_session() -> None:
    session = Mock(spec=Session)

    repository = SqlAlchemyIngestionRunRepository(
        session=session,
    )

    run_id = repository.create(
        IngestionRunData(
            source_id=uuid4(),
            status="running",
            connector_version="1.0.0",
        )
    )

    assert run_id is not None
    session.add.assert_called_once()
    session.flush.assert_called_once_with()
    session.commit.assert_not_called()


def test_mark_completed_updates_run() -> None:
    session = Mock(spec=Session)

    execute_result = Mock()
    execute_result.rowcount = 1
    session.execute.return_value = execute_result

    repository = SqlAlchemyIngestionRunRepository(
        session=session,
    )

    updated = repository.mark_completed(
        run_id=uuid4(),
        finished_at=datetime.now(UTC),
        records_received=10,
        records_succeeded=9,
        records_failed=1,
    )

    assert updated is True
    session.execute.assert_called_once()
    session.flush.assert_called_once_with()
    session.commit.assert_not_called()

def test_mark_failed_updates_run() -> None:
    session = Mock(spec=Session)

    execute_result = Mock()
    execute_result.scalar_one_or_none.return_value = uuid4()
    session.execute.return_value = execute_result

    repository = SqlAlchemyIngestionRunRepository(
        session=session,
    )

    updated = repository.mark_failed(
        run_id=uuid4(),
        finished_at=datetime.now(UTC),
        error_summary="Connector timeout",
        records_received=10,
        records_succeeded=7,
        records_failed=3,
    )

    assert updated is True
    session.execute.assert_called_once()
    execute_result.scalar_one_or_none.assert_called_once_with()
    session.flush.assert_called_once_with()
    session.commit.assert_not_called()
def test_mark_failed_returns_false_when_run_does_not_exist() -> None:
    session = Mock(spec=Session)

    execute_result = Mock()
    execute_result.scalar_one_or_none.return_value = None
    session.execute.return_value = execute_result

    repository = SqlAlchemyIngestionRunRepository(
        session=session,
    )

    updated = repository.mark_failed(
        run_id=uuid4(),
        finished_at=datetime.now(UTC),
        error_summary="Unknown run",
    )

    assert updated is False
    session.flush.assert_called_once_with()
    session.commit.assert_not_called()