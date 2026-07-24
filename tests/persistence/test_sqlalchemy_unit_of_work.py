from unittest.mock import Mock

import pytest
from sqlalchemy.orm import Session, sessionmaker

from infrastructure.persistence.sqlalchemy.unit_of_work import (
    SqlAlchemyUnitOfWork,
)


def test_commit_delegates_to_session() -> None:
    session = Mock(spec=Session)
    session_factory = Mock(
        spec=sessionmaker,
        return_value=session,
    )

    unit_of_work = SqlAlchemyUnitOfWork(
        session_factory=session_factory,
    )

    with unit_of_work:
        unit_of_work.commit()

    session.commit.assert_called_once_with()
    session.close.assert_called_once_with()


def test_exit_rolls_back_when_commit_is_not_called() -> None:
    session = Mock(spec=Session)
    session_factory = Mock(
        spec=sessionmaker,
        return_value=session,
    )

    unit_of_work = SqlAlchemyUnitOfWork(
        session_factory=session_factory,
    )

    with unit_of_work:
        pass

    session.rollback.assert_called_once_with()
    session.close.assert_called_once_with()


def test_exit_rolls_back_on_exception() -> None:
    session = Mock(spec=Session)
    session_factory = Mock(
        spec=sessionmaker,
        return_value=session,
    )

    unit_of_work = SqlAlchemyUnitOfWork(
        session_factory=session_factory,
    )

    with pytest.raises(ValueError):
        with unit_of_work:
            raise ValueError("test failure")

    session.rollback.assert_called_once_with()
    session.commit.assert_not_called()
    session.close.assert_called_once_with()


def test_commit_outside_context_is_rejected() -> None:
    session_factory = Mock(spec=sessionmaker)

    unit_of_work = SqlAlchemyUnitOfWork(
        session_factory=session_factory,
    )

    with pytest.raises(
        RuntimeError,
        match="Unit of Work is not active",
    ):
        unit_of_work.commit()