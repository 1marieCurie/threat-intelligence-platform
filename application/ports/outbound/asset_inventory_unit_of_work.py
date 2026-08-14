from __future__ import annotations

from types import TracebackType
from typing import Protocol, Self

from application.ports.outbound.asset_inventory_repository import (
    AssetInventoryRepository,
)


class AssetInventoryUnitOfWork(Protocol):
    """
    Frontière transactionnelle du core asset/inventory.

    Le repository est exposé en lecture seule depuis
    la perspective du service applicatif.
    """

    @property
    def asset_inventory(
        self,
    ) -> AssetInventoryRepository:
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

    def rollback(
        self,
    ) -> None:
        ...