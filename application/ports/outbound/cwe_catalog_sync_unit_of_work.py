from __future__ import annotations

from collections.abc import Iterable
from types import TracebackType
from typing import Protocol, Self

from application.ports.outbound.cwe_reference_repository import (
    VulnerabilityCWEReferenceRepository,
)
from domain.cwe_weakness import CWEWeakness


class CWEWeaknessBatchWriter(Protocol):
        
    """
    Port minimal de lecture et d'écriture utilisé
    par la synchronisation du catalogue CWE.
    """
    
    def find_many_by_ids(
        self,
        cwe_ids: Iterable[str],
    ) -> list[CWEWeakness]:
        """
        Retourne en une lecture bornée les CWE déjà persistés.
        """
        ...

    def upsert_many(
        self,
        weaknesses: Iterable[CWEWeakness],
    ) -> int:
        """
        Insère ou actualise plusieurs faiblesses CWE.
        """
        ...


class CWECatalogSyncUnitOfWork(Protocol):
    """
    Unit of Work minimal nécessaire à la synchronisation CWE.

    L'utilisation de propriétés en lecture seule évite les problèmes
    d'invariance liés aux attributs mutables des Protocols.
    """

    @property
    def vulnerability_cwe_references(
        self,
    ) -> VulnerabilityCWEReferenceRepository:
        """
        Repository des identifiants CWE référencés.
        """
        ...

    @property
    def cwe_weaknesses(
        self,
    ) -> CWEWeaknessBatchWriter:
        """
        Repository d'écriture du catalogue CWE.
        """
        ...

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