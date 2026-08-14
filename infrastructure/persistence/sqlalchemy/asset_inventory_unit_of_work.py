from __future__ import annotations

from collections.abc import Callable
from types import TracebackType
from typing import Self

from sqlalchemy.exc import (
    IntegrityError,
    SQLAlchemyError,
)
from sqlalchemy.orm import Session

from application.ports.outbound.asset_inventory_repository import (
    AssetInventoryConflictError,
    AssetInventoryRepository,
    AssetInventoryRepositoryError,
)
from infrastructure.persistence.sqlalchemy.repositories.asset_inventory_repository import (
    SqlAlchemyAssetInventoryRepository,
)


SessionFactory = Callable[[], Session]


class SqlAlchemyAssetInventoryUnitOfWork:
    """
    Unit of Work dédiée au core asset/inventory.

    Une entrée de contexte :
        une Session SQLAlchemy
        une transaction PostgreSQL
        un AssetInventoryRepository
    """

    def __init__(
        self,
        session_factory: SessionFactory,
    ) -> None:
        if session_factory is None:
            raise ValueError(
                "session_factory must not be None"
            )

        self._session_factory = (
            session_factory
        )

        self._session: Session | None = None

        self._asset_inventory: (
            SqlAlchemyAssetInventoryRepository
            | None
        ) = None

    @property
    def asset_inventory(
        self,
    ) -> AssetInventoryRepository:
        if self._asset_inventory is None:
            raise RuntimeError(
                "Unit of Work is not active"
            )

        return self._asset_inventory

    def __enter__(
        self,
    ) -> Self:
        if self._session is not None:
            raise RuntimeError(
                "Unit of Work is already active"
            )

        self._session = (
            self._session_factory()
        )

        self._asset_inventory = (
            SqlAlchemyAssetInventoryRepository(
                session=self._session
            )
        )

        return self

    def __exit__(
        self,
        exc_type: type[
            BaseException
        ] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        try:
            if self._session is not None:
                self._session.rollback()

        finally:
            if self._session is not None:
                self._session.close()

            self._session = None
            self._asset_inventory = None

    def commit(
        self,
    ) -> None:
        session = self._require_session()

        try:
            session.commit()

        except IntegrityError as error:
            session.rollback()

            raise AssetInventoryConflictError(
                "Asset inventory database "
                "constraint conflict"
            ) from error

        except SQLAlchemyError as error:
            session.rollback()

            raise AssetInventoryRepositoryError(
                "Unable to commit "
                "asset inventory"
            ) from error

    def rollback(
        self,
    ) -> None:
        session = self._require_session()

        try:
            session.rollback()

        except SQLAlchemyError as error:
            raise AssetInventoryRepositoryError(
                "Unable to rollback "
                "asset inventory transaction"
            ) from error

    def _require_session(
        self,
    ) -> Session:
        if self._session is None:
            raise RuntimeError(
                "Unit of Work is not active"
            )

        return self._session