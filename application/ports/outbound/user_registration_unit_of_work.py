from __future__ import annotations

from types import TracebackType
from typing import (
    Protocol,
    Self,
)

from application.ports.outbound.user_registration_repository import (
    UserRegistrationRepository,
)


class UserRegistrationUnitOfWork(
    Protocol
):
    @property
    def registration(
        self,
    ) -> UserRegistrationRepository:
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