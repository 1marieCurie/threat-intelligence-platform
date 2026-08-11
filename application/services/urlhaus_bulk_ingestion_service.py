from collections.abc import (
Iterable,
Iterator,
)
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from uuid import UUID

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
)
from application.ports.outbound.unit_of_work import (
UnitOfWork,
)

DEFAULT_DUMP_SCOPE = (
"active_or_last_90_days"
)

SUPPORTED_DUMP_SCOPES = frozenset(
{
"active_only",
"active_or_last_90_days",
}
)

class URLhausBulkRecord(Protocol):
    external_record_id: str
    payload: dict[str, object]
    retrieved_at: datetime
    source_url: str


@dataclass(
    frozen=True,
    slots=True,
)
class URLhausBulkIngestionResult:
    run_id: UUID
    records_received: int
    records_inserted: int
    records_existing: int
    batches_processed: int


class URLhausBulkIngestionService:
    """
    Persiste un dump URLhaus en streaming.

    ```
    Chaque batch possède une transaction PostgreSQL courte.
    Le run n'est marqué completed qu'après consommation
    complète du dump.
    """

    DEFAULT_BATCH_SIZE = 500
    MAX_BATCH_SIZE = 5_000

    CONNECTOR_VERSION = (
        "urlhaus-dump-csv/2.1.0"
    )

    def __init__(
        self,
        *,
        unit_of_work: UnitOfWork,
        payload_hasher: PayloadHasher,
        batch_size: int = DEFAULT_BATCH_SIZE,
    ) -> None:
        if unit_of_work is None:
            raise ValueError(
                "unit_of_work must not be None"
            )

        if payload_hasher is None:
            raise ValueError(
                "payload_hasher must not be None"
            )

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

        if not (
            1
            <= batch_size
            <= self.MAX_BATCH_SIZE
        ):
            raise ValueError(
                "batch_size must be between 1 "
                f"and {self.MAX_BATCH_SIZE}"
            )

        self._unit_of_work = (
            unit_of_work
        )

        self._payload_hasher = (
            payload_hasher
        )

        self._batch_size = batch_size

    def ingest(
        self,
        *,
        source_id: UUID,
        records: Iterable[
            URLhausBulkRecord
        ],
        dump_scope: str = DEFAULT_DUMP_SCOPE,
    ) -> URLhausBulkIngestionResult:
        if not isinstance(
            source_id,
            UUID,
        ):
            raise TypeError(
                "source_id must be a UUID"
            )

        normalized_dump_scope = (
            self._validate_dump_scope(
                dump_scope
            )
        )

        run_id = self._start_run(
            source_id=source_id,
            dump_scope=(
                normalized_dump_scope
            ),
        )

        records_received = 0
        records_inserted = 0
        records_existing = 0
        batches_processed = 0

        try:
            for batch in self._iter_batches(
                records
            ):
                (
                    inserted,
                    existing,
                ) = self._persist_batch(
                    source_id=source_id,
                    run_id=run_id,
                    records=batch,
                )

                records_received += len(
                    batch
                )

                records_inserted += inserted
                records_existing += existing

                batches_processed += 1

            self._complete_run(
                run_id=run_id,
                dump_scope=(
                    normalized_dump_scope
                ),
                records_received=(
                    records_received
                ),
                records_succeeded=(
                    records_received
                ),
                records_inserted=(
                    records_inserted
                ),
                records_existing=(
                    records_existing
                ),
                batches_processed=(
                    batches_processed
                ),
            )

            return URLhausBulkIngestionResult(
                run_id=run_id,
                records_received=(
                    records_received
                ),
                records_inserted=(
                    records_inserted
                ),
                records_existing=(
                    records_existing
                ),
                batches_processed=(
                    batches_processed
                ),
            )

        except Exception:
            self._mark_failed(
                run_id=run_id,
                records_received=(
                    records_received
                ),
            )

            raise

    def _start_run(
        self,
        *,
        source_id: UUID,
        dump_scope: str,
    ) -> UUID:
        with self._unit_of_work as uow:
            run_id = (
                uow.ingestion_runs.create(
                    IngestionRunData(
                        source_id=source_id,
                        status="running",
                        connector_version=(
                            self.CONNECTOR_VERSION
                        ),
                        metadata={
                            "collection_mode": (
                                "database_dump"
                            ),
                            "dump_scope": (
                                dump_scope
                            ),
                            "historical_complete": (
                                False
                            ),
                        },
                    )
                )
            )

            uow.commit()

        return run_id

    def _persist_batch(
        self,
        *,
        source_id: UUID,
        run_id: UUID,
        records: tuple[
            URLhausBulkRecord,
            ...,
        ],
    ) -> tuple[int, int]:
        payloads = tuple(
            RawPayloadData(
                source_id=source_id,
                ingestion_run_id=run_id,
                external_record_id=(
                    record.external_record_id
                ),
                payload=dict(
                    record.payload
                ),
                payload_hash=(
                    self._payload_hasher.hash(
                        record.payload
                    )
                ),
                retrieved_at=(
                    record.retrieved_at
                ),
                request_url=(
                    record.source_url
                ),
                http_status=200,
            )
            for record in records
        )

        with self._unit_of_work as uow:
            result = (
                uow.raw_payloads
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
                        records[0]
                        .retrieved_at
                    ),
                )
                for reference
                in result.references
            )

            link_result = (
                uow.ingestion_run_payloads
                .link_many_ignore_existing(
                    links
                )
            )

            if (
                link_result.unique_count
                != len(result.references)
            ):
                raise RuntimeError(
                    "Unable to link all "
                    "URLhaus dump payloads"
                )

            uow.commit()

        return (
            result.inserted_count,
            result.skipped_count,
        )

    def _complete_run(
        self,
        *,
        run_id: UUID,
        dump_scope: str,
        records_received: int,
        records_succeeded: int,
        records_inserted: int,
        records_existing: int,
        batches_processed: int,
    ) -> None:
        finished_at = datetime.now(
            UTC
        )

        metadata = {
            "collection_mode": (
                "database_dump"
            ),
            "dump_scope": (
                dump_scope
            ),
            "historical_complete": False,
            "window_complete": True,
            "records_inserted": (
                records_inserted
            ),
            "records_existing": (
                records_existing
            ),
            "batches_processed": (
                batches_processed
            ),
            "batch_size": (
                self._batch_size
            ),
        }

        with self._unit_of_work as uow:
            updated = (
                uow.ingestion_runs
                .mark_completed(
                    run_id=run_id,
                    finished_at=(
                        finished_at
                    ),
                    records_received=(
                        records_received
                    ),
                    records_succeeded=(
                        records_succeeded
                    ),
                    records_failed=0,
                    connector_version=(
                        self.CONNECTOR_VERSION
                    ),
                    metadata=metadata,
                )
            )

            if not updated:
                raise RuntimeError(
                    "Unable to complete "
                    "URLhaus dump run"
                )

            uow.commit()

    def _mark_failed(
        self,
        *,
        run_id: UUID,
        records_received: int,
    ) -> None:
        try:
            with self._unit_of_work as uow:
                uow.ingestion_runs.mark_failed(
                    run_id=run_id,
                    finished_at=(
                        datetime.now(UTC)
                    ),
                    error_summary=(
                        "URLhaus bulk ingestion "
                        "failed"
                    ),
                    records_received=(
                        records_received
                    ),
                    records_succeeded=(
                        records_received
                    ),
                    records_failed=0,
                )

                uow.commit()

        except Exception:
            # Ne masque jamais l'erreur originale.
            pass

    def _iter_batches(
        self,
        records: Iterable[
            URLhausBulkRecord
        ],
    ) -> Iterator[
        tuple[
            URLhausBulkRecord,
            ...,
        ]
    ]:
        batch: list[
            URLhausBulkRecord
        ] = []

        for record in records:
            batch.append(record)

            if (
                len(batch)
                >= self._batch_size
            ):
                yield tuple(batch)
                batch.clear()

        if batch:
            yield tuple(batch)

    @staticmethod
    def _validate_dump_scope(
        value: str,
    ) -> str:
        if not isinstance(
            value,
            str,
        ):
            raise TypeError(
                "dump_scope must be a string"
            )

        normalized = value.strip()

        if (
            normalized
            not in SUPPORTED_DUMP_SCOPES
        ):
            raise ValueError(
                "dump_scope must be one of: "
                "active_only, "
                "active_or_last_90_days"
            )

        return normalized

