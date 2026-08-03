from __future__ import annotations

from unittest.mock import Mock
from uuid import uuid4

from sqlalchemy.orm import (
    Session,
    sessionmaker,
)

from infrastructure.persistence.sqlalchemy.repositories.urlhaus_url_repository import (
    SqlAlchemyURLhausURLRepository,
)
from infrastructure.persistence.sqlalchemy.unit_of_work import (
    SqlAlchemyUnitOfWork,
)


def test_context_initializes_urlhaus_repository(
) -> None:
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
            unit_of_work.urlhaus_urls,
            SqlAlchemyURLhausURLRepository,
        )

    session.rollback.assert_called_once_with()
    session.close.assert_called_once_with()


def test_urlhaus_repository_uses_unit_of_work_session(
) -> None:
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

    payload_id = uuid4()

    with unit_of_work:
        result = (
            unit_of_work
            .urlhaus_urls
            .exists_by_raw_payload_id(
                payload_id
            )
        )

        assert result is False

    session.execute.assert_called_once()
    session.rollback.assert_called_once_with()
    session.close.assert_called_once_with()