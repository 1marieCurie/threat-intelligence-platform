from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from application.ports.outbound.ingestion_connector import (
    IngestionConnector,
)
from application.ports.outbound.ingestion_run_repository import (
    IngestionRunData,
)
from application.ports.outbound.payload_hasher import (
    PayloadHasher,
)
from application.ports.outbound.raw_payload_repository import (
    RawPayloadData,
)
from application.ports.outbound.sync_state_repository import (
    SyncStateData,
)
from application.ports.outbound.unit_of_work import (
    UnitOfWork,
)
from application.ports.outbound.ingestion_connector import (
    FetchResult,
    IngestionConnector,
)
from application.ports.outbound.sync_state_repository import (
    SyncStateData,
)


@dataclass(frozen=True, slots=True)
class IngestionResult:
    run_id: UUID
    records_received: int
    records_persisted: int
    records_skipped: int
    status: str


class IngestionService:
    def __init__(
        self,
        *,
        unit_of_work: UnitOfWork,
        connector: IngestionConnector,
        payload_hasher: PayloadHasher,
    ) -> None:
        self._unit_of_work = unit_of_work
        self._connector = connector
        self._payload_hasher = payload_hasher

    def _start_run(
        self,
        *,
        source_id: UUID,
    ) -> UUID:
        with self._unit_of_work as unit_of_work:
            run_id = unit_of_work.ingestion_runs.create(
                IngestionRunData(
                    source_id=source_id,
                    status="running",
                )
            )

            unit_of_work.commit()

        return run_id
    
    def _persist_fetch_result(
        self,
        *,
        source_id: UUID,
        run_id: UUID,
        fetch_result: FetchResult,
    ) -> IngestionResult:
        completed_at = datetime.now(UTC)

        records_persisted = 0
        records_skipped = 0

        with self._unit_of_work as unit_of_work:
            for record in fetch_result.records:
                payload_hash = self._payload_hasher.hash(
                    record.payload
                )

                already_exists = (
                    unit_of_work.raw_payloads
                    .exists_by_identity(
                        source_id=source_id,
                        external_record_id=(
                            record.external_record_id
                        ),
                        payload_hash=payload_hash,
                    )
                )

                if already_exists:
                    records_skipped += 1
                    continue

                unit_of_work.raw_payloads.save(
                    RawPayloadData(
                        source_id=source_id,
                        ingestion_run_id=run_id,
                        external_record_id=(
                            record.external_record_id
                        ),
                        payload=record.payload,
                        payload_hash=payload_hash,
                        http_status=record.http_status,
                    )
                )

                records_persisted += 1

            unit_of_work.sync_states.upsert(
                SyncStateData(
                    source_id=source_id,
                    cursor=fetch_result.next_cursor,
                    last_attempt_at=completed_at,
                    last_success_at=completed_at,
                    metadata=fetch_result.metadata,
                )
            )

            records_received = len(
                fetch_result.records
            )

            updated = (
                unit_of_work.ingestion_runs
                .mark_completed(
                    run_id=run_id,
                    finished_at=completed_at,
                    records_received=records_received,
                    records_succeeded=records_persisted,
                    records_failed=0,
                )
            )

            if not updated:
                raise RuntimeError(
                    "Unable to complete ingestion run"
                )

            unit_of_work.commit()

        return IngestionResult(
            run_id=run_id,
            records_received=records_received,
            records_persisted=records_persisted,
            records_skipped=records_skipped,
            status="completed",
        )
    def _mark_run_failed(
        self,
        *,
        run_id: UUID,
        error: Exception,
    ) -> None:
        failed_at = datetime.now(UTC)

        error_summary = self._build_error_summary(
            error
        )

        with self._unit_of_work as unit_of_work:
            updated = (
                unit_of_work.ingestion_runs.mark_failed(
                    run_id=run_id,
                    finished_at=failed_at,
                    error_summary=error_summary,
                )
            )

            if not updated:
                raise RuntimeError(
                    "Unable to mark ingestion run as failed"
                ) from error

            unit_of_work.commit()
    @staticmethod
    def _build_error_summary(
        error: Exception,
    ) -> str:
        error_type = type(error).__name__
        message = str(error).strip()

        if not message:
            return error_type

        sanitized_message = message[:500]

        return f"{error_type}: {sanitized_message}"
    
    def ingest(
        self,
        *,
        source_id: UUID,
    ) -> IngestionResult:
        sync_state = self._read_sync_state(
        source_id=source_id,
    )

        cursor = (
            sync_state.cursor
            if sync_state is not None
            else None
        )

        state_metadata = (
            sync_state.metadata
            if sync_state is not None
            else None
        )

        run_id = self._start_run(
            source_id=source_id,
        )

        try:
            fetch_result = self._connector.fetch(
                cursor=cursor,
                state_metadata=state_metadata,
            )

            return self._persist_fetch_result(
                source_id=source_id,
                run_id=run_id,
                fetch_result=fetch_result,
            )

        except Exception as error:
            self._mark_run_failed(
                run_id=run_id,
                error=error,
            )
            raise

    def _read_sync_state(
        self,
        *,
        source_id: UUID,
    ) -> SyncStateData | None:
        with self._unit_of_work as unit_of_work:
            return (
                unit_of_work.sync_states
                .get_by_source_id(source_id)
            )