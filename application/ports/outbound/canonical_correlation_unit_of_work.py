from __future__ import annotations

from types import TracebackType
from typing import (
    Protocol,
    Self,
)

from application.ports.outbound.canonical_vulnerability_repository import (
    CanonicalVulnerabilityRepository,
)


class CanonicalCorrelationUnitOfWork(
    Protocol
):
    """
    Frontière transactionnelle minimale nécessaire
    au service de corrélation canonique.

    Le service ne doit pas dépendre des repositories
    d'ingestion, EPSS, CISA ou GitHub Advisory.
    """

    canonical_vulnerabilities: (
        CanonicalVulnerabilityRepository
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