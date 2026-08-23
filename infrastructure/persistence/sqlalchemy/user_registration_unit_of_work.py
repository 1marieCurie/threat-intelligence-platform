from __future__ import annotations

from collections.abc import Callable
from types import TracebackType
from typing import Self

from sqlalchemy.exc import (
    IntegrityError,
    SQLAlchemyError,
)
from sqlalchemy.orm import Session

from application.ports.outbound.user_registration_repository import (
    UserRegistrationConflictError,
    UserRegistrationRepository,
    UserRegistrationRepositoryError,
)
from infrastructure.persistence.sqlalchemy.repositories.user_registration_repository import (
    SqlAlchemyUserRegistrationRepository,
)


SessionFactory = Callable[
    [],
    Session,
]


class SqlAlchemyUserRegistrationUnitOfWork:
    def __init__(
        self,
        session_factory: SessionFactory,
    ) -> None:
        if session_factory is None:
            raise ValueError(
                (
                    "session_factory "
                    "must not be None"
                )
            )

        self._session_factory = (
            session_factory
        )

        self._session: (
            Session | None
        ) = None

        self._registration: (
            SqlAlchemyUserRegistrationRepository
            | None
        ) = None

    @property
    def registration(
        self,
    ) -> UserRegistrationRepository:
        if (
            self._registration
            is None
        ):
            raise RuntimeError(
                (
                    "Unit of Work "
                    "is not active"
                )
            )

        return self._registration

    def __enter__(
        self,
    ) -> Self:
        if self._session is not None:
            raise RuntimeError(
                (
                    "Unit of Work "
                    "is already active"
                )
            )

        self._session = (
            self._session_factory()
        )

        self._registration = (
            SqlAlchemyUserRegistrationRepository(
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
            self._registration = None

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

            raise (
                UserRegistrationConflictError(
                    (
                        "Registration database "
                        "constraint conflict"
                    )
                )
            ) from error

        except SQLAlchemyError as error:
            session.rollback()

            raise (
                UserRegistrationRepositoryError(
                    (
                        "Unable to commit "
                        "registration transaction"
                    )
                )
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
            raise (
                UserRegistrationRepositoryError(
                    (
                        "Unable to rollback "
                        "registration transaction"
                    )
                )
            ) from error

    def _require_session(
        self,
    ) -> Session:
        if self._session is None:
            raise RuntimeError(
                (
                    "Unit of Work "
                    "is not active"
                )
            )

        return self._session