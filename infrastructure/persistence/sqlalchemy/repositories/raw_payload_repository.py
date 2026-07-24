from __future__ import annotations

from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from application.ports.outbound.raw_payload_repository import (
    RawPayloadData,
)
from infrastructure.persistence.models.raw import (
    SourcePayloadModel,
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