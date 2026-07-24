from __future__ import annotations

from datetime import datetime
from uuid import UUID, uuid4

from sqlalchemy import update
from sqlalchemy.orm import Session

from application.ports.outbound.ingestion_run_repository import (
    IngestionRunData,
)
from infrastructure.persistence.models.ops import (
    IngestionRunModel,
)


class SqlAlchemyIngestionRunRepository:
    def __init__(
        self,
        session: Session,
    ) -> None:
        self._session = session

    def create(
        self,
        run: IngestionRunData,
    ) -> UUID:
        run_id = uuid4()

        model = IngestionRunModel(
            id=run_id,
            source_id=run.source_id,
            status=run.status,
            finished_at=run.finished_at,
            records_received=run.records_received,
            records_succeeded=run.records_succeeded,
            records_failed=run.records_failed,
            error_summary=run.error_summary,
            connector_version=run.connector_version,
        )

        if run.started_at is not None:
            model.started_at = run.started_at

        self._session.add(model)
        self._session.flush()

        return run_id

    def mark_completed(
        self,
        *,
        run_id: UUID,
        finished_at: datetime,
        records_received: int,
        records_succeeded: int,
        records_failed: int,
    ) -> bool:
        statement = (
            update(IngestionRunModel)
            .where(IngestionRunModel.id == run_id)
            .values(
                status="completed",
                finished_at=finished_at,
                records_received=records_received,
                records_succeeded=records_succeeded,
                records_failed=records_failed,
                error_summary=None,
            )
            .returning(IngestionRunModel.id)
        )

        updated_id = self._session.execute(
            statement
        ).scalar_one_or_none()

        self._session.flush()

        return updated_id is not None

    def mark_failed(
        self,
        *,
        run_id: UUID,
        finished_at: datetime,
        error_summary: str,
        records_received: int = 0,
        records_succeeded: int = 0,
        records_failed: int = 0,
    ) -> bool:
        statement = (
            update(IngestionRunModel)
            .where(IngestionRunModel.id == run_id)
            .values(
                status="failed",
                finished_at=finished_at,
                records_received=records_received,
                records_succeeded=records_succeeded,
                records_failed=records_failed,
                error_summary=error_summary,
            )
            .returning(IngestionRunModel.id)
        )

        updated_id = self._session.execute(
            statement
        ).scalar_one_or_none()

        self._session.flush()

        return updated_id is not None

