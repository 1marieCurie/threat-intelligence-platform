from __future__ import annotations

from types import TracebackType
from typing import Self

from sqlalchemy.orm import (
    Session,
    sessionmaker,
)

from application.ports.outbound.alert_repository import (
    AlertRepository,
)
from application.ports.outbound.security_responsible_read_repository import (
    SecurityResponsibleReadRepository,
)
from infrastructure.persistence.sqlalchemy.repositories.alert_repository import (
    SqlAlchemyAlertRepository,
)
from infrastructure.persistence.sqlalchemy.repositories.security_responsible_read_repository import (
    SqlAlchemySecurityResponsibleReadRepository,
)


SessionFactory = sessionmaker[Session]


class SqlAlchemyAlertUnitOfWork:
    def __init__(
        self,
        *,
        session_factory: SessionFactory,
    ) -> None:
        if session_factory is None:
            raise ValueError(
                "session_factory must not be None"
            )

        self._session_factory = (
            session_factory
        )

        self._session: Session | None = None

        self._alerts: (
            AlertRepository
            | None
        ) = None

        self._security_responsibles: (
            SecurityResponsibleReadRepository
            | None
        ) = None

    def __enter__(
        self,
    ) -> Self:
        if self._session is not None:
            raise RuntimeError(
                "Unit of work is already active"
            )

        session = (
            self._session_factory()
        )

        self._session = session

        self._alerts = (
            SqlAlchemyAlertRepository(
                session=session
            )
        )

        self._security_responsibles = (
            SqlAlchemySecurityResponsibleReadRepository(
                session=session
            )
        )

        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del traceback

        try:
            if (
                exc_type is not None
                or exc_value is not None
            ):
                self.rollback()
        finally:
            self._close()

    @property
    def alerts(
        self,
    ) -> AlertRepository:
        repository = self._alerts

        if repository is None:
            raise RuntimeError(
                "Unit of work is not active"
            )

        return repository

    @property
    def security_responsibles(
        self,
    ) -> SecurityResponsibleReadRepository:
        repository = (
            self._security_responsibles
        )

        if repository is None:
            raise RuntimeError(
                "Unit of work is not active"
            )

        return repository

    def commit(
        self,
    ) -> None:
        session = (
            self._require_session()
        )

        session.commit()

    def rollback(
        self,
    ) -> None:
        if self._session is not None:
            self._session.rollback()

    def _require_session(
        self,
    ) -> Session:
        if self._session is None:
            raise RuntimeError(
                "Unit of work is not active"
            )

        return self._session

    def _close(
        self,
    ) -> None:
        session = self._session

        self._session = None
        self._alerts = None
        self._security_responsibles = None

        if session is not None:
            session.close()