from __future__ import annotations

from types import TracebackType
from typing import (
    Protocol,
    Self,
)

from application.ports.outbound.authentication_repository import (
    AuthenticationRepository,
)


class AuthenticationUnitOfWork(
    Protocol
):
    @property
    def authentication(
        self,
    ) -> AuthenticationRepository:
        ...

    def __enter__(
        self,
    ) -> Self:
        ...

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
        ...

    def commit(
        self,
    ) -> None:
        ...

    def rollback(
        self,
    ) -> None:
        ...