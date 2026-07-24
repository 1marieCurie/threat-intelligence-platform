from datetime import UTC, datetime
from unittest.mock import Mock
from uuid import uuid4

from sqlalchemy.orm import Session

from application.ports.outbound.sync_state_repository import (
    SyncStateData,
)
from infrastructure.persistence.sqlalchemy.repositories.sync_state_repository import (
    SqlAlchemySyncStateRepository,
)


def test_upsert_executes_statement_and_flushes() -> None:
    session = Mock(spec=Session)

    repository = SqlAlchemySyncStateRepository(
        session=session,
    )

    repository.upsert(
        SyncStateData(
            source_id=uuid4(),
            cursor="cursor-001",
            last_success_at=datetime.now(UTC),
            metadata={
                "page": 10,
            },
        )
    )

    session.execute.assert_called_once()
    session.flush.assert_called_once_with()
    session.commit.assert_not_called()


def test_mark_attempt_executes_statement_and_flushes() -> None:
    session = Mock(spec=Session)

    repository = SqlAlchemySyncStateRepository(
        session=session,
    )

    repository.mark_attempt(
        source_id=uuid4(),
        attempted_at=datetime.now(UTC),
    )

    session.execute.assert_called_once()
    session.flush.assert_called_once_with()
    session.commit.assert_not_called()


def test_get_by_source_id_returns_none_when_missing() -> None:
    session = Mock(spec=Session)

    execute_result = Mock()
    execute_result.scalar_one_or_none.return_value = None
    session.execute.return_value = execute_result

    repository = SqlAlchemySyncStateRepository(
        session=session,
    )

    result = repository.get_by_source_id(
        uuid4()
    )

    assert result is None