from __future__ import annotations

from typing import cast
from datetime import datetime
from uuid import UUID

from sqlalchemy import Table, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from application.ports.outbound.sync_state_repository import (
    SyncStateData,
)
from infrastructure.persistence.models.ops import (
    SyncStateModel,
)


class SqlAlchemySyncStateRepository:
    def __init__(
        self,
        session: Session,
    ) -> None:
        self._session = session

    def get_by_source_id(
        self,
        source_id: UUID,
    ) -> SyncStateData | None:
        statement = (
            select(SyncStateModel)
            .where(
                SyncStateModel.source_id == source_id
            )
        )

        model = self._session.execute(
            statement
        ).scalar_one_or_none()

        if model is None:
            return None

        return SyncStateData(
            source_id=model.source_id,
            cursor=model.cursor,
            last_success_at=model.last_success_at,
            last_attempt_at=model.last_attempt_at,
            metadata=dict(model.metadata_),
        )

    def upsert(
        self,
        state: SyncStateData,
    ) -> None:
        metadata_value = state.metadata or {}

        table = cast(
            Table,
            SyncStateModel.__table__,
        )

        statement = (
            insert(table)
            .values(
                source_id=state.source_id,
                cursor=state.cursor,
                last_success_at=state.last_success_at,
                last_attempt_at=state.last_attempt_at,
                metadata=metadata_value,
            )
            .on_conflict_do_update(
                index_elements=[
                    table.c.source_id,
                ],
                set_={
                    "cursor": state.cursor,
                    "last_success_at": state.last_success_at,
                    "last_attempt_at": state.last_attempt_at,
                    "metadata": metadata_value,
                },
            )
        )

        self._session.execute(statement)
        self._session.flush()

    def mark_attempt(
        self,
        *,
        source_id: UUID,
        attempted_at: datetime,
    ) -> None:
        table = cast(
            Table,
            SyncStateModel.__table__,
        )

        statement = (
            insert(table)
            .values(
                source_id=source_id,
                last_attempt_at=attempted_at,
                metadata={},
            )
            .on_conflict_do_update(
                index_elements=[
                    table.c.source_id,
                ],
                set_={
                    "last_attempt_at": attempted_at,
                },
            )
        )

        self._session.execute(statement)
        self._session.flush()