from __future__ import annotations

from collections.abc import Callable
from types import TracebackType
from typing import Self

from sqlalchemy.exc import (
    IntegrityError,
    SQLAlchemyError,
)
from sqlalchemy.orm import Session

from application.ports.outbound.authentication_repository import (
    AuthenticationConflictError,
    AuthenticationRepository,
    AuthenticationRepositoryError,
)
from infrastructure.persistence.sqlalchemy.repositories.authentication_repository import (
    SqlAlchemyAuthenticationRepository,
)


SessionFactory = Callable[
    [],
    Session,
]


class SqlAlchemyAuthenticationUnitOfWork:
    def __init__(
        self,
        session_factory: SessionFactory,
    ) -> None:
        if session_factory is None:
            raise ValueError(
                "session_factory must not be None"
            )

        self._session_factory = (
            session_factory
        )

        self._session: (
            Session | None
        ) = None

        self._authentication: (
            SqlAlchemyAuthenticationRepository
            | None
        ) = None

    @property
    def authentication(
        self,
    ) -> AuthenticationRepository:
        if (
            self._authentication
            is None
        ):
            raise RuntimeError(
                "Unit of Work is not active"
            )

        return self._authentication

    def __enter__(
        self,
    ) -> Self:
        if self._session is not None:
            raise RuntimeError(
                "Unit of Work is already active"
            )

        self._session = (
            self._session_factory()
        )

        self._authentication = (
            SqlAlchemyAuthenticationRepository(
                session=(
                    self._session
                )
            )
        )

        return self

    def __exit__(
        self,
        exc_type: (
            type[BaseException]
            | None
        ),
        exc_value: (
            BaseException
            | None
        ),
        traceback: (
            TracebackType
            | None
        ),
    ) -> None:
        del exc_type
        del exc_value
        del traceback

        try:
            if self._session is not None:
                self._session.rollback()

        finally:
            if self._session is not None:
                self._session.close()

            self._session = None
            self._authentication = None

    def commit(
        self,
    ) -> None:
        session = (
            self._require_session()
        )

        try:
            session.commit()

        except IntegrityError as error:
            session.rollback()

            raise AuthenticationConflictError(
                "Authentication database "
                "constraint conflict"
            ) from error

        except SQLAlchemyError as error:
            session.rollback()

            raise AuthenticationRepositoryError(
                "Unable to commit "
                "authentication transaction"
            ) from error

    def rollback(
        self,
    ) -> None:
        session = (
            self._require_session()
        )

        try:
            session.rollback()

        except SQLAlchemyError as error:
            raise AuthenticationRepositoryError(
                "Unable to rollback "
                "authentication transaction"
            ) from error

    def _require_session(
        self,
    ) -> Session:
        if self._session is None:
            raise RuntimeError(
                "Unit of Work is not active"
            )

        return self._session