from __future__ import annotations

from types import TracebackType
from typing import (
    Protocol,
    Self,
)

from application.ports.outbound.canonical_vulnerability_weakness_repository import (
    CanonicalVulnerabilityWeaknessRepository,
)


class CanonicalCWEEnrichmentUnitOfWork(
    Protocol
):
    """
    Frontière transactionnelle minimale nécessaire
    à l'enrichissement canonique CWE.

    Le service ne dépend pas des repositories
    d'ingestion ou de corrélation.
    """

    canonical_vulnerability_weaknesses: (
        CanonicalVulnerabilityWeaknessRepository
    )

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

    def commit(
        self,
    ) -> None:
        ...

    def rollback(
        self,
    ) -> None:
        ...