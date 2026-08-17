from __future__ import annotations

from types import TracebackType
from typing import Protocol, Self

from application.ports.outbound.alert_repository import (
    AlertRepository,
)
from application.ports.outbound.security_responsible_read_repository import (
    SecurityResponsibleReadRepository,
)


class AlertUnitOfWork(
    Protocol
):
    def __enter__(
        self,
    ) -> Self:
        ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        ...

    @property
    def alerts(
        self,
    ) -> AlertRepository:
        ...

    @property
    def security_responsibles(
        self,
    ) -> SecurityResponsibleReadRepository:
        ...

    def commit(
        self,
    ) -> None:
        ...

    def rollback(
        self,
    ) -> None:
        ...