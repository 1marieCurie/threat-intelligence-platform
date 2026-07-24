from __future__ import annotations

from types import TracebackType
from typing import Protocol, Self

from application.ports.outbound.raw_payload_repository import (
    RawPayloadRepository,
)


class UnitOfWork(Protocol):
    raw_payloads: RawPayloadRepository

    def __enter__(self) -> Self:
        ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        ...

    def commit(self) -> None:
        ...

    def rollback(self) -> None:
        ...