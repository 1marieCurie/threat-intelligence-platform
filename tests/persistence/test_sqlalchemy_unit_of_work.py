from unittest.mock import Mock

import pytest
from sqlalchemy.orm import Session, sessionmaker

from infrastructure.persistence.sqlalchemy.repositories.cisa_kev_vulnerability_repository import (
    SqlAlchemyCisaKevVulnerabilityRepository,
)
from infrastructure.persistence.sqlalchemy.repositories.epss_score_repository import (
    SqlAlchemyEPSSScoreRepository,
)
from infrastructure.persistence.sqlalchemy.unit_of_work import (
    SqlAlchemyUnitOfWork,
)


def test_commit_delegates_to_session() -> None:
    session = Mock(
        spec=Session,
    )
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
    session = Mock(
        spec=Session,
    )
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
    session = Mock(
        spec=Session,
    )
    session_factory = Mock(
        spec=sessionmaker,
        return_value=session,
    )

    unit_of_work = SqlAlchemyUnitOfWork(
        session_factory=session_factory,
    )

    with pytest.raises(
        ValueError,
    ):
        with unit_of_work:
            raise ValueError(
                "test failure"
            )

    session.rollback.assert_called_once_with()
    session.commit.assert_not_called()
    session.close.assert_called_once_with()


def test_commit_outside_context_is_rejected() -> None:
    session_factory = Mock(
        spec=sessionmaker,
    )

    unit_of_work = SqlAlchemyUnitOfWork(
        session_factory=session_factory,
    )

    with pytest.raises(
        RuntimeError,
        match="Unit of Work is not active",
    ):
        unit_of_work.commit()


def test_context_initializes_cisa_repository() -> None:
    session = Mock(
        spec=Session,
    )

    session_factory = Mock(
        spec=sessionmaker,
        return_value=session,
    )

    unit_of_work = SqlAlchemyUnitOfWork(
        session_factory=session_factory,
    )

    with unit_of_work:
        assert isinstance(
            unit_of_work.cisa_kev_vulnerabilities,
            SqlAlchemyCisaKevVulnerabilityRepository,
        )

    session.rollback.assert_called_once_with()
    session.close.assert_called_once_with()


def test_context_initializes_epss_repository() -> None:
    session = Mock(
        spec=Session,
    )

    session_factory = Mock(
        spec=sessionmaker,
        return_value=session,
    )

    unit_of_work = SqlAlchemyUnitOfWork(
        session_factory=session_factory,
    )

    with unit_of_work:
        assert isinstance(
            unit_of_work.epss_scores,
            SqlAlchemyEPSSScoreRepository,
        )

    session.rollback.assert_called_once_with()
    session.close.assert_called_once_with()


def test_epss_repository_uses_unit_of_work_session() -> None:
    session = Mock(
        spec=Session,
    )

    session.execute.return_value \
        .scalar_one_or_none.return_value = None

    session_factory = Mock(
        spec=sessionmaker,
        return_value=session,
    )

    unit_of_work = SqlAlchemyUnitOfWork(
        session_factory=session_factory,
    )

    with unit_of_work:
        result = (
            unit_of_work
            .epss_scores
            .find_by_cve_id(
                "CVE-2021-44228"
            )
        )

        assert result is None

    session.execute.assert_called_once()
    session.rollback.assert_called_once_with()
    session.close.assert_called_once_with()
    
    
def test_unit_of_work_rejects_nested_context() -> None:
    session = Mock(
        spec=Session,
    )

    session_factory = Mock(
        spec=sessionmaker,
        return_value=session,
    )

    unit_of_work = SqlAlchemyUnitOfWork(
        session_factory=session_factory,
    )

    with unit_of_work:
        with pytest.raises(
            RuntimeError,
            match=(
                "Unit of Work is already active"
            ),
        ):
            unit_of_work.__enter__()

    session.rollback.assert_called_once_with()
    session.close.assert_called_once_with()