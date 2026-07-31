from __future__ import annotations

from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID

from application.ports.outbound.ingestion_connector import (
    FetchedRecord,
    FetchResult,
    IngestionConnector,
)
from application.ports.outbound.ingestion_run_payload_repository import (
    IngestionRunPayloadLink,
)
from application.ports.outbound.ingestion_run_repository import (
    IngestionRunData,
)
from application.ports.outbound.payload_hasher import (
    PayloadHasher,
)
from application.ports.outbound.raw_payload_repository import (
    RawPayloadData,
    RawPayloadIdentity,
)
from application.ports.outbound.sync_state_repository import (
    SyncStateData,
)
from application.ports.outbound.unit_of_work import (
    UnitOfWork,
)
from application.security.sensitive_data_redactor import (
    redact_sensitive_data,
)


@dataclass(
    frozen=True,
    slots=True,
)
class IngestionResult:
    run_id: UUID
    records_received: int
    records_persisted: int
    records_skipped: int
    status: str
    pagination_complete: bool = True


@dataclass(
    slots=True,
)
class _IngestionProgress:
    """
    État interne de progression d'un run.

    Ces compteurs permettent de conserver une observabilité
    exacte lorsqu'une défaillance survient entre deux lots.
    """

    records_received: int = 0
    records_persisted: int = 0
    records_skipped: int = 0

    @property
    def records_failed(self) -> int:
        """
        Retourne les enregistrements qui n'ont été ni persistés
        ni identifiés comme déjà existants.
        """
        return max(
            self.records_received
            - self.records_persisted
            - self.records_skipped,
            0,
        )


class IngestionService:
    """
    Orchestre une ingestion brute générique.

    Les appels fournisseurs et les calculs de hash sont exécutés
    hors transaction PostgreSQL.

    Les payloads et leurs liens avec le run sont persistés par
    lots bornés dans des transactions courtes.
    """

    DEFAULT_BATCH_SIZE = 500
    MAX_BATCH_SIZE = 5_000

    def __init__(
        self,
        *,
        unit_of_work: UnitOfWork,
        connector: IngestionConnector,
        payload_hasher: PayloadHasher,
        batch_size: int = DEFAULT_BATCH_SIZE,
    ) -> None:
        if unit_of_work is None:
            raise ValueError(
                "unit_of_work must not be None"
            )

        if connector is None:
            raise ValueError(
                "connector must not be None"
            )

        if payload_hasher is None:
            raise ValueError(
                "payload_hasher must not be None"
            )

        self._validate_batch_size(
            batch_size
        )

        self._unit_of_work = unit_of_work
        self._connector = connector
        self._payload_hasher = payload_hasher
        self._batch_size = batch_size

    def ingest(
        self,
        *,
        source_id: UUID,
    ) -> IngestionResult:
        self._validate_source_id(
            source_id
        )

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

        progress = _IngestionProgress()

        try:
            # Aucun appel fournisseur dans une transaction SQL.
            fetch_result = self._connector.fetch(
                cursor=cursor,
                state_metadata=state_metadata,
            )

            progress.records_received = len(
                fetch_result.records
            )

            return self._persist_fetch_result(
                source_id=source_id,
                run_id=run_id,
                fetch_result=fetch_result,
                progress=progress,
            )

        except Exception as error:
            self._mark_run_failed(
                run_id=run_id,
                error=error,
                progress=progress,
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
                .get_by_source_id(
                    source_id
                )
            )

    def _start_run(
        self,
        *,
        source_id: UUID,
    ) -> UUID:
        with self._unit_of_work as unit_of_work:
            run_id = (
                unit_of_work.ingestion_runs
                .create(
                    IngestionRunData(
                        source_id=source_id,
                        status="running",
                    )
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
        progress: _IngestionProgress,
    ) -> IngestionResult:
        if not isinstance(
            fetch_result,
            FetchResult,
        ):
            raise TypeError(
                "connector result must be a FetchResult"
            )

        for record_batch in self._iter_batches(
            fetch_result.records
        ):
            # Le calcul des hash reste hors transaction SQL.
            prepared_payloads = self._prepare_batch(
                source_id=source_id,
                run_id=run_id,
                records=record_batch,
            )

            (
                batch_persisted,
                batch_skipped,
            ) = self._persist_batch(
                run_id=run_id,
                payloads=prepared_payloads,
            )

            # Mise à jour uniquement après le commit du lot.
            progress.records_persisted += (
                batch_persisted
            )

            progress.records_skipped += (
                batch_skipped
            )

        completed_at = datetime.now(
            UTC
        )

        self._complete_run(
            source_id=source_id,
            run_id=run_id,
            fetch_result=fetch_result,
            completed_at=completed_at,
            progress=progress,
        )

        return IngestionResult(
            run_id=run_id,
            records_received=(
                progress.records_received
            ),
            records_persisted=(
                progress.records_persisted
            ),
            records_skipped=(
                progress.records_skipped
            ),
            status="completed",
            pagination_complete=(
                fetch_result.next_cursor is None
            ),
        )

    def _prepare_batch(
        self,
        *,
        source_id: UUID,
        run_id: UUID,
        records: Sequence[FetchedRecord],
    ) -> tuple[RawPayloadData, ...]:
        payloads: list[RawPayloadData] = []

        for record in records:
            if not isinstance(
                record,
                FetchedRecord,
            ):
                raise TypeError(
                    "Every fetched record must be "
                    "a FetchedRecord"
                )

            payload_hash = (
                self._payload_hasher.hash(
                    record.payload
                )
            )

            payloads.append(
                RawPayloadData(
                    source_id=source_id,
                    ingestion_run_id=run_id,
                    external_record_id=(
                        record.external_record_id
                    ),
                    payload=record.payload,
                    payload_hash=payload_hash,
                    retrieved_at=record.fetched_at,
                    request_url=record.source_url,
                    http_status=record.http_status,
                )
            )

        return tuple(
            payloads
        )

    def _persist_batch(
        self,
        *,
        run_id: UUID,
        payloads: Sequence[RawPayloadData],
    ) -> tuple[int, int]:
        """
        Persiste un lot de payloads et leurs observations dans
        une transaction unique et bornée.
        """
        if not payloads:
            return 0, 0

        observation_times = (
            self._build_observation_times(
                payloads
            )
        )

        with self._unit_of_work as unit_of_work:
            batch_result = (
                unit_of_work.raw_payloads
                .save_many_ignore_existing(
                    payloads
                )
            )

            links = tuple(
                IngestionRunPayloadLink(
                    ingestion_run_id=run_id,
                    raw_payload_id=(
                        reference.payload_id
                    ),
                    observed_at=(
                        observation_times.get(
                            reference.identity
                        )
                    ),
                )
                for reference
                in batch_result.references
            )

            link_result = (
                unit_of_work
                .ingestion_run_payloads
                .link_many_ignore_existing(
                    links
                )
            )

            if (
                link_result.unique_count
                != len(
                    batch_result.references
                )
            ):
                raise RuntimeError(
                    "Unable to link all raw payload "
                    "observations to the ingestion run"
                )

            unit_of_work.commit()

        return (
            batch_result.inserted_count,
            batch_result.skipped_count,
        )

    def _complete_run(
        self,
        *,
        source_id: UUID,
        run_id: UUID,
        fetch_result: FetchResult,
        completed_at: datetime,
        progress: _IngestionProgress,
    ) -> None:
        metadata = dict(
            fetch_result.metadata
        )

        metadata.update(
            {
                "records_persisted": (
                    progress.records_persisted
                ),
                "records_skipped": (
                    progress.records_skipped
                ),
                "batch_size": self._batch_size,
            }
        )

        with self._unit_of_work as unit_of_work:
            unit_of_work.sync_states.upsert(
                SyncStateData(
                    source_id=source_id,
                    cursor=fetch_result.next_cursor,
                    last_attempt_at=completed_at,
                    last_success_at=completed_at,
                    metadata=metadata,
                )
            )

            updated = (
                unit_of_work.ingestion_runs
                .mark_completed(
                    run_id=run_id,
                    finished_at=completed_at,
                    records_received=(
                        progress.records_received
                    ),
                    records_succeeded=(
                        progress.records_persisted
                    ),
                    records_failed=0,
                    connector_version=(
                        fetch_result.connector_version
                    ),
                    metadata=metadata,
                )
            )

            if not updated:
                raise RuntimeError(
                    "Unable to complete ingestion run"
                )

            unit_of_work.commit()

    def _mark_run_failed(
        self,
        *,
        run_id: UUID,
        error: Exception,
        progress: _IngestionProgress,
    ) -> None:
        failed_at = datetime.now(
            UTC
        )

        error_summary = (
            self._build_error_summary(
                error
            )
        )

        with self._unit_of_work as unit_of_work:
            updated = (
                unit_of_work.ingestion_runs
                .mark_failed(
                    run_id=run_id,
                    finished_at=failed_at,
                    error_summary=error_summary,
                    records_received=(
                        progress.records_received
                    ),
                    records_succeeded=(
                        progress.records_persisted
                    ),
                    records_failed=(
                        progress.records_failed
                    ),
                )
            )

            if not updated:
                raise RuntimeError(
                    "Unable to mark ingestion "
                    "run as failed"
                ) from error

            unit_of_work.commit()

    def _iter_batches(
        self,
        records: Sequence[FetchedRecord],
    ) -> Iterator[
        Sequence[FetchedRecord]
    ]:
        for start in range(
            0,
            len(records),
            self._batch_size,
        ):
            yield records[
                start:
                start + self._batch_size
            ]

    @staticmethod
    def _build_observation_times(
        payloads: Sequence[RawPayloadData],
    ) -> dict[
        RawPayloadIdentity,
        datetime | None,
    ]:
        observation_times: dict[
            RawPayloadIdentity,
            datetime | None,
        ] = {}

        for payload in payloads:
            external_record_id = (
                payload.external_record_id
            )

            if external_record_id is None:
                raise ValueError(
                    "external_record_id is required "
                    "for batch ingestion"
                )

            identity = RawPayloadIdentity(
                source_id=payload.source_id,
                external_record_id=(
                    external_record_id.strip()
                ),
                payload_hash=(
                    payload.payload_hash.strip()
                ),
            )

            observation_times.setdefault(
                identity,
                payload.retrieved_at,
            )

        return observation_times

    @staticmethod
    def _build_error_summary(
        error: Exception,
    ) -> str:
        error_type = type(
            error
        ).__name__

        message = str(
            error
        ).strip()

        if not message:
            return error_type

        sanitized_message = (
            redact_sensitive_data(
                message,
                max_length=500,
            )
        )

        return (
            f"{error_type}: "
            f"{sanitized_message}"
        )

    @staticmethod
    def _validate_source_id(
        source_id: UUID,
    ) -> None:
        if not isinstance(
            source_id,
            UUID,
        ):
            raise TypeError(
                "source_id must be a UUID"
            )

    @classmethod
    def _validate_batch_size(
        cls,
        batch_size: int,
    ) -> None:
        if (
            isinstance(batch_size, bool)
            or not isinstance(
                batch_size,
                int,
            )
        ):
            raise TypeError(
                "batch_size must be an integer"
            )

        if batch_size < 1:
            raise ValueError(
                "batch_size must be greater than zero"
            )

        if batch_size > cls.MAX_BATCH_SIZE:
            raise ValueError(
                "batch_size must not exceed 5000"
            )