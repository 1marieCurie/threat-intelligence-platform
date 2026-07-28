from __future__ import annotations

from uuid import UUID, uuid4

from sqlalchemy import select, update
from sqlalchemy.orm import Session
from typing import Sequence

from application.ports.outbound.raw_payload_repository import (
    RawPayloadData,
)
from infrastructure.persistence.models.raw import (
    SourcePayloadModel,
)
from application.ports.outbound.raw_payload_repository import (
    PersistedRawPayload,
    RawPayloadData,
)



class SqlAlchemyRawPayloadRepository:
    def __init__(
        self,
        session: Session,
    ) -> None:
        if not isinstance(session, Session):
            raise TypeError(
                "session must be a SQLAlchemy Session"
            )

        self._session = session

    def save(
        self,
        payload: RawPayloadData,
    ) -> UUID:
        payload_id = uuid4()

        model = SourcePayloadModel(
            id=payload_id,
            source_id=payload.source_id,
            ingestion_run_id=payload.ingestion_run_id,
            external_record_id=payload.external_record_id,
            request_url=payload.request_url,
            http_status=payload.http_status,
            payload=payload.payload,
            payload_hash=payload.payload_hash,
            source_updated_at=payload.source_updated_at,
            processing_status=payload.processing_status,
            error_message=payload.error_message,
        )

        if payload.retrieved_at is not None:
            model.retrieved_at = payload.retrieved_at

        self._session.add(model)
        self._session.flush()

        return payload_id

    def exists_by_identity(
        self,
        *,
        source_id: UUID,
        external_record_id: str | None,
        payload_hash: str,
    ) -> bool:
        statement = (
            select(SourcePayloadModel.id)
            .where(
                SourcePayloadModel.source_id == source_id,
                SourcePayloadModel.external_record_id
                == external_record_id,
                SourcePayloadModel.payload_hash
                == payload_hash,
            )
            .limit(1)
        )

        return (
            self._session.execute(statement).scalar_one_or_none()
            is not None
        )
    def claim_pending(
        self,
        *,
        source_id: UUID,
        limit: int,
    ) -> Sequence[PersistedRawPayload]:
        if isinstance(limit, bool) or not isinstance(limit, int):
            raise TypeError("limit must be an integer")

        if limit <= 0:
            raise ValueError("limit must be greater than zero")

        statement = (
            select(SourcePayloadModel)
            .where(
                SourcePayloadModel.source_id == source_id,
                SourcePayloadModel.processing_status == "pending",
            )
            .order_by(
                SourcePayloadModel.retrieved_at.asc(),
                SourcePayloadModel.id.asc(),
            )
            .limit(limit)
            .with_for_update(skip_locked=True)
        )

        models = list(
            self._session.execute(statement)
            .scalars()
            .all()
        )

        for model in models:
            model.processing_status = "processing"
            model.error_message = None

        self._session.flush()

        return [
            self._to_persisted_payload(model)
            for model in models
        ]
    @staticmethod
    def _to_persisted_payload(
        model: SourcePayloadModel,
    ) -> PersistedRawPayload:
        return PersistedRawPayload(
            id=model.id,
            source_id=model.source_id,
            ingestion_run_id=model.ingestion_run_id,
            external_record_id=model.external_record_id,
            retrieved_at=model.retrieved_at,
            request_url=model.request_url,
            http_status=model.http_status,
            payload=model.payload,
            payload_hash=model.payload_hash,
            source_updated_at=model.source_updated_at,
            processing_status=model.processing_status,
            error_message=model.error_message,
        )
    
    def mark_processed(
        self,
        *,
        payload_id: UUID,
    ) -> bool:
        return self._transition_from_processing(
            payload_id=payload_id,
            target_status="processed",
            error_message=None,
        )


    def mark_failed(
        self,
        *,
        payload_id: UUID,
        error_message: str,
    ) -> bool:
        if not isinstance(error_message, str):
            raise TypeError("error_message must be a string")

        normalized_error = error_message.strip()

        if not normalized_error:
            raise ValueError("error_message must not be empty")

        return self._transition_from_processing(
            payload_id=payload_id,
            target_status="failed",
            error_message=normalized_error,
        )


    def _transition_from_processing(
        self,
        *,
        payload_id: UUID,
        target_status: str,
        error_message: str | None,
    ) -> bool:
        statement = (
            update(SourcePayloadModel)
            .where(
                SourcePayloadModel.id == payload_id,
                SourcePayloadModel.processing_status
                == "processing",
            )
            .values(
                processing_status=target_status,
                error_message=error_message,
            )
            .returning(SourcePayloadModel.id)
        )

        updated_payload_id = (
            self._session.execute(statement)
            .scalar_one_or_none()
        )

        return updated_payload_id is not None