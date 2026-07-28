from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import case, select, update
from sqlalchemy.orm import Session

from application.ports.outbound.raw_payload_repository import (
    PersistedRawPayload,
    RawPayloadData,
    RawPayloadRecoveryResult,
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
                SourcePayloadModel.source_id
                == source_id,
                SourcePayloadModel.external_record_id
                == external_record_id,
                SourcePayloadModel.payload_hash
                == payload_hash,
            )
            .limit(1)
        )

        existing_id = (
            self._session
            .execute(statement)
            .scalar_one_or_none()
        )

        return existing_id is not None

    def claim_pending(
        self,
        *,
        source_id: UUID,
        limit: int,
    ) -> tuple[PersistedRawPayload, ...]:
        self._validate_source_id(
            source_id
        )
        self._validate_limit(
            limit
        )

        statement = (
            select(SourcePayloadModel)
            .where(
                SourcePayloadModel.source_id
                == source_id,
                SourcePayloadModel.processing_status
                == "pending",
            )
            .order_by(
                SourcePayloadModel.retrieved_at,
                SourcePayloadModel.id,
            )
            .limit(limit)
            .with_for_update(
                skip_locked=True,
            )
        )

        models = tuple(
            self._session
            .execute(statement)
            .scalars()
            .all()
        )

        processing_started_at = datetime.now(
            UTC
        )

        for model in models:
            model.processing_status = "processing"
            model.processing_started_at = (
                processing_started_at
            )
            model.processing_attempts += 1
            model.error_message = None

        self._session.flush()

        return tuple(
            self._to_persisted_payload(model)
            for model in models
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
            raise TypeError(
                "error_message must be a string"
            )

        normalized_error = error_message.strip()

        if not normalized_error:
            raise ValueError(
                "error_message must not be empty"
            )

        return self._transition_from_processing(
            payload_id=payload_id,
            target_status="failed",
            error_message=normalized_error,
        )

    def recover_stale_processing(
        self,
        *,
        source_id: UUID,
        stale_before: datetime,
        max_attempts: int,
        failure_message: str,
    ) -> RawPayloadRecoveryResult:
        self._validate_source_id(
            source_id
        )
        self._validate_stale_before(
            stale_before
        )
        self._validate_max_attempts(
            max_attempts
        )

        normalized_failure_message = (
            self._normalize_failure_message(
                failure_message
            )
        )

        reached_attempt_limit = (
            SourcePayloadModel.processing_attempts
            >= max_attempts
        )

        next_status = case(
            (
                reached_attempt_limit,
                "failed",
            ),
            else_="pending",
        )

        next_error_message = case(
            (
                reached_attempt_limit,
                normalized_failure_message,
            ),
            else_=None,
        )

        statement = (
            update(SourcePayloadModel)
            .where(
                SourcePayloadModel.source_id
                == source_id,
                SourcePayloadModel.processing_status
                == "processing",
                SourcePayloadModel
                .processing_started_at
                .is_not(None),
                SourcePayloadModel
                .processing_started_at
                < stale_before,
            )
            .values(
                processing_status=next_status,
                processing_started_at=None,
                error_message=next_error_message,
            )
            .returning(
                SourcePayloadModel.processing_status
            )
        )

        resulting_statuses = tuple(
            self._session
            .execute(statement)
            .scalars()
            .all()
        )

        self._session.flush()

        return RawPayloadRecoveryResult(
            requeued=sum(
                status == "pending"
                for status in resulting_statuses
            ),
            failed=sum(
                status == "failed"
                for status in resulting_statuses
            ),
        )

    def _transition_from_processing(
        self,
        *,
        payload_id: UUID,
        target_status: str,
        error_message: str | None,
    ) -> bool:
        if not isinstance(payload_id, UUID):
            raise TypeError(
                "payload_id must be a UUID"
            )

        statement = (
            update(SourcePayloadModel)
            .where(
                SourcePayloadModel.id
                == payload_id,
                SourcePayloadModel.processing_status
                == "processing",
            )
            .values(
                processing_status=target_status,
                processing_started_at=None,
                error_message=error_message,
            )
            .returning(
                SourcePayloadModel.id
            )
        )

        updated_payload_id = (
            self._session
            .execute(statement)
            .scalar_one_or_none()
        )

        return updated_payload_id is not None

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
            processing_started_at=(
                model.processing_started_at
            ),
            processing_attempts=(
                model.processing_attempts
            ),
            error_message=model.error_message,
        )

    @staticmethod
    def _validate_source_id(
        source_id: UUID,
    ) -> None:
        if not isinstance(source_id, UUID):
            raise TypeError(
                "source_id must be a UUID"
            )

    @staticmethod
    def _validate_limit(
        limit: int,
    ) -> None:
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
        ):
            raise TypeError(
                "limit must be an integer"
            )

        if limit < 1:
            raise ValueError(
                "limit must be greater than zero"
            )

    @staticmethod
    def _validate_stale_before(
        stale_before: datetime,
    ) -> None:
        if not isinstance(
            stale_before,
            datetime,
        ):
            raise TypeError(
                "stale_before must be a datetime"
            )

        if (
            stale_before.tzinfo is None
            or stale_before.utcoffset() is None
        ):
            raise ValueError(
                "stale_before must be timezone-aware"
            )

    @staticmethod
    def _validate_max_attempts(
        max_attempts: int,
    ) -> None:
        if (
            isinstance(max_attempts, bool)
            or not isinstance(max_attempts, int)
        ):
            raise TypeError(
                "max_attempts must be an integer"
            )

        if max_attempts < 1:
            raise ValueError(
                "max_attempts must be greater than zero"
            )

    @staticmethod
    def _normalize_failure_message(
        failure_message: str,
    ) -> str:
        if not isinstance(
            failure_message,
            str,
        ):
            raise TypeError(
                "failure_message must be a string"
            )

        normalized = failure_message.strip()

        if not normalized:
            raise ValueError(
                "failure_message must not be empty"
            )

        return normalized