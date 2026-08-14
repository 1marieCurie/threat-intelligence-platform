from __future__ import annotations

from types import TracebackType
from typing import Protocol, Self

from application.ports.outbound.asset_inventory_repository import (
    AssetInventoryRepository,
)


class AssetInventoryUnitOfWork(Protocol):
    """
    Frontière transactionnelle de l'import machine inventory/v1.

    Machine, état courant et composants doivent être persistés
    dans la même transaction.
    """

    asset_inventory: AssetInventoryRepository

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