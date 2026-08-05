from __future__ import annotations

from types import TracebackType
from typing import (
    Protocol,
    Self,
    runtime_checkable,
)

from application.ports.outbound.canonical_web_indicator_repository import (
    CanonicalWebIndicatorRepository,
)


@runtime_checkable
class CanonicalWebIndicatorUnitOfWork(
    Protocol
):
    """
    Frontière transactionnelle de la corrélation Web.

    Une instance ne doit pas être réutilisée simultanément
    par plusieurs threads ou workers.
    """

    canonical_web_indicators: (
        CanonicalWebIndicatorRepository
    )

    def __enter__(
        self,
    ) -> Self:
        ...

    def __exit__(
        self,
        exception_type: type[
            BaseException
        ] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
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