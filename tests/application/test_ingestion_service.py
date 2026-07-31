from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import Mock
from uuid import UUID, uuid4

import pytest

from application.ports.outbound.ingestion_connector import (
    FetchedRecord,
    FetchResult,
)
from application.ports.outbound.ingestion_run_payload_repository import (
    IngestionRunPayloadBatchResult,
)
from application.ports.outbound.raw_payload_repository import (
    PersistedRawPayloadReference,
    RawPayloadBatchSaveResult,
    RawPayloadIdentity,
)
from application.ports.outbound.sync_state_repository import (
    SyncStateData,
)
from application.services.ingestion_service import (
    IngestionService,
)


def _build_unit_of_work() -> Mock:
    unit_of_work = Mock()

    unit_of_work.__enter__ = Mock(
        return_value=unit_of_work,
    )

    unit_of_work.__exit__ = Mock(
        return_value=None,
    )

    return unit_of_work


def _build_batch_result(
    *,
    source_id: UUID,
    external_record_id: str,
    payload_hash: str,
    inserted: bool,
    payload_id: UUID | None = None,
) -> RawPayloadBatchSaveResult:
    identity = RawPayloadIdentity(
        source_id=source_id,
        external_record_id=external_record_id,
        payload_hash=payload_hash,
    )

    return RawPayloadBatchSaveResult(
        submitted_count=1,
        references=(
            PersistedRawPayloadReference(
                payload_id=(
                    payload_id
                    if payload_id is not None
                    else uuid4()
                ),
                identity=identity,
                inserted=inserted,
            ),
        ),
    )


def _configure_link_result(
    unit_of_work: Mock,
    *,
    inserted_count: int = 1,
) -> None:
    (
        unit_of_work
        .ingestion_run_payloads
        .link_many_ignore_existing
        .return_value
    ) = IngestionRunPayloadBatchResult(
        submitted_count=1,
        unique_count=1,
        inserted_count=inserted_count,
    )


def test_ingest_persists_new_records_and_commits() -> None:
    source_id = uuid4()
    run_id = uuid4()
    payload_id = uuid4()

    fetched_at = datetime(
        2026,
        7,
        28,
        14,
        0,
        tzinfo=UTC,
    )

    source_url = (
        "https://www.cisa.gov/"
        "known_exploited_vulnerabilities.json"
    )

    unit_of_work = _build_unit_of_work()

    (
        unit_of_work
        .sync_states
        .get_by_source_id
        .return_value
    ) = SyncStateData(
        source_id=source_id,
        cursor="cursor-001",
    )

    (
        unit_of_work
        .ingestion_runs
        .create
        .return_value
    ) = run_id

    (
        unit_of_work
        .raw_payloads
        .save_many_ignore_existing
        .return_value
    ) = _build_batch_result(
        source_id=source_id,
        external_record_id="CVE-2026-0001",
        payload_hash="a" * 64,
        inserted=True,
        payload_id=payload_id,
    )

    _configure_link_result(
        unit_of_work
    )

    (
        unit_of_work
        .ingestion_runs
        .mark_completed
        .return_value
    ) = True

    connector = Mock()

    connector.fetch.return_value = FetchResult(
        records=[
            FetchedRecord(
                external_record_id="CVE-2026-0001",
                payload={
                    "id": "CVE-2026-0001",
                },
                source_url=source_url,
                fetched_at=fetched_at,
                http_status=200,
            )
        ],
        next_cursor="cursor-002",
        metadata={
            "page": 2,
        },
        connector_version="1.0.0",
    )

    payload_hasher = Mock()
    payload_hasher.hash.return_value = (
        "a" * 64
    )

    service = IngestionService(
        unit_of_work=unit_of_work,
        connector=connector,
        payload_hasher=payload_hasher,
    )

    result = service.ingest(
        source_id=source_id,
    )

    connector.fetch.assert_called_once_with(
        cursor="cursor-001",
        state_metadata=None,
    )

    (
        unit_of_work
        .raw_payloads
        .exists_by_identity
        .assert_not_called()
    )

    (
        unit_of_work
        .raw_payloads
        .save
        .assert_not_called()
    )

    (
        unit_of_work
        .raw_payloads
        .save_many_ignore_existing
        .assert_called_once()
    )

    saved_payloads = (
        unit_of_work
        .raw_payloads
        .save_many_ignore_existing
        .call_args
        .args[0]
    )

    assert len(saved_payloads) == 1

    saved_payload = saved_payloads[0]

    assert saved_payload.source_id == source_id
    assert saved_payload.ingestion_run_id == run_id

    assert (
        saved_payload.external_record_id
        == "CVE-2026-0001"
    )

    assert (
        saved_payload.request_url
        == source_url
    )

    assert (
        saved_payload.retrieved_at
        == fetched_at
    )

    assert saved_payload.http_status == 200

    assert (
        saved_payload.payload_hash
        == "a" * 64
    )

    (
        unit_of_work
        .ingestion_run_payloads
        .link_many_ignore_existing
        .assert_called_once()
    )

    links = (
        unit_of_work
        .ingestion_run_payloads
        .link_many_ignore_existing
        .call_args
        .args[0]
    )

    assert len(links) == 1
    assert links[0].ingestion_run_id == run_id
    assert links[0].raw_payload_id == payload_id
    assert links[0].observed_at == fetched_at

    (
        unit_of_work
        .sync_states
        .upsert
        .assert_called_once()
    )

    (
        unit_of_work
        .ingestion_runs
        .mark_completed
        .assert_called_once()
    )

    # Création du run, persistance du lot, finalisation.
    assert unit_of_work.commit.call_count == 3

    assert result.run_id == run_id
    assert result.records_received == 1
    assert result.records_persisted == 1
    assert result.records_skipped == 0
    assert result.status == "completed"

    completed_call = (
        unit_of_work
        .ingestion_runs
        .mark_completed
        .call_args
        .kwargs
    )

    assert (
        completed_call["connector_version"]
        == "1.0.0"
    )

    assert completed_call["metadata"] == {
        "page": 2,
        "records_persisted": 1,
        "records_skipped": 0,
        "batch_size": 500,
    }


def test_ingest_links_existing_payload_to_new_run() -> None:
    source_id = uuid4()
    run_id = uuid4()
    existing_payload_id = uuid4()

    high_water_mark = (
        "2026-07-24T10:00:00Z"
    )

    unit_of_work = _build_unit_of_work()

    (
        unit_of_work
        .sync_states
        .get_by_source_id
        .return_value
    ) = SyncStateData(
        source_id=source_id,
        cursor="cursor-001",
        metadata={
            "high_water_mark": high_water_mark,
        },
    )

    (
        unit_of_work
        .ingestion_runs
        .create
        .return_value
    ) = run_id

    (
        unit_of_work
        .raw_payloads
        .save_many_ignore_existing
        .return_value
    ) = _build_batch_result(
        source_id=source_id,
        external_record_id="CVE-2026-0001",
        payload_hash="b" * 64,
        inserted=False,
        payload_id=existing_payload_id,
    )

    _configure_link_result(
        unit_of_work
    )

    (
        unit_of_work
        .ingestion_runs
        .mark_completed
        .return_value
    ) = True

    connector = Mock()

    connector.fetch.return_value = FetchResult(
        records=[
            FetchedRecord(
                external_record_id="CVE-2026-0001",
                payload={
                    "id": "CVE-2026-0001",
                },
            )
        ],
        next_cursor="cursor-002",
    )

    payload_hasher = Mock()
    payload_hasher.hash.return_value = (
        "b" * 64
    )

    service = IngestionService(
        unit_of_work=unit_of_work,
        connector=connector,
        payload_hasher=payload_hasher,
    )

    result = service.ingest(
        source_id=source_id,
    )

    connector.fetch.assert_called_once_with(
        cursor="cursor-001",
        state_metadata={
            "high_water_mark": high_water_mark,
        },
    )

    (
        unit_of_work
        .raw_payloads
        .save_many_ignore_existing
        .assert_called_once()
    )

    (
        unit_of_work
        .ingestion_run_payloads
        .link_many_ignore_existing
        .assert_called_once()
    )

    links = (
        unit_of_work
        .ingestion_run_payloads
        .link_many_ignore_existing
        .call_args
        .args[0]
    )

    assert links[0].raw_payload_id == existing_payload_id
    assert links[0].ingestion_run_id == run_id

    (
        unit_of_work
        .raw_payloads
        .save
        .assert_not_called()
    )

    (
        unit_of_work
        .raw_payloads
        .exists_by_identity
        .assert_not_called()
    )

    assert unit_of_work.commit.call_count == 3

    assert result.records_received == 1
    assert result.records_persisted == 0
    assert result.records_skipped == 1
    assert result.status == "completed"


def test_ingest_marks_run_failed_when_connector_fails() -> None:
    source_id = uuid4()
    run_id = uuid4()

    unit_of_work = _build_unit_of_work()

    (
        unit_of_work
        .sync_states
        .get_by_source_id
        .return_value
    ) = SyncStateData(
        source_id=source_id,
        cursor="cursor-001",
    )

    (
        unit_of_work
        .ingestion_runs
        .create
        .return_value
    ) = run_id

    (
        unit_of_work
        .ingestion_runs
        .mark_failed
        .return_value
    ) = True

    connector = Mock()

    connector.fetch.side_effect = RuntimeError(
        "Connector unavailable"
    )

    payload_hasher = Mock()

    service = IngestionService(
        unit_of_work=unit_of_work,
        connector=connector,
        payload_hasher=payload_hasher,
    )

    with pytest.raises(
        RuntimeError,
        match="Connector unavailable",
    ):
        service.ingest(
            source_id=source_id,
        )

    connector.fetch.assert_called_once_with(
        cursor="cursor-001",
        state_metadata=None,
    )

    (
        unit_of_work
        .ingestion_runs
        .mark_failed
        .assert_called_once()
    )

    failed_call = (
        unit_of_work
        .ingestion_runs
        .mark_failed
        .call_args
        .kwargs
    )

    assert failed_call["run_id"] == run_id

    assert (
        failed_call["error_summary"]
        == "RuntimeError: Connector unavailable"
    )

    (
        unit_of_work
        .sync_states
        .upsert
        .assert_not_called()
    )

    (
        unit_of_work
        .raw_payloads
        .save_many_ignore_existing
        .assert_not_called()
    )

    (
        unit_of_work
        .ingestion_run_payloads
        .link_many_ignore_existing
        .assert_not_called()
    )

    # Création du run puis statut failed.
    assert unit_of_work.commit.call_count == 2


def test_ingest_marks_run_failed_when_batch_persistence_fails() -> None:
    source_id = uuid4()
    run_id = uuid4()

    unit_of_work = _build_unit_of_work()

    (
        unit_of_work
        .sync_states
        .get_by_source_id
        .return_value
    ) = None

    (
        unit_of_work
        .ingestion_runs
        .create
        .return_value
    ) = run_id

    (
        unit_of_work
        .raw_payloads
        .save_many_ignore_existing
        .side_effect
    ) = RuntimeError(
        "Database write failed"
    )

    (
        unit_of_work
        .ingestion_runs
        .mark_failed
        .return_value
    ) = True

    connector = Mock()

    connector.fetch.return_value = FetchResult(
        records=[
            FetchedRecord(
                external_record_id="CVE-2026-0002",
                payload={
                    "id": "CVE-2026-0002",
                },
            )
        ],
    )

    payload_hasher = Mock()
    payload_hasher.hash.return_value = (
        "c" * 64
    )

    service = IngestionService(
        unit_of_work=unit_of_work,
        connector=connector,
        payload_hasher=payload_hasher,
    )

    with pytest.raises(
        RuntimeError,
        match="Database write failed",
    ):
        service.ingest(
            source_id=source_id,
        )

    connector.fetch.assert_called_once_with(
        cursor=None,
        state_metadata=None,
    )

    (
        unit_of_work
        .sync_states
        .upsert
        .assert_not_called()
    )

    (
        unit_of_work
        .ingestion_run_payloads
        .link_many_ignore_existing
        .assert_not_called()
    )

    (
        unit_of_work
        .ingestion_runs
        .mark_failed
        .assert_called_once()
    )

    failed_call = (
        unit_of_work
        .ingestion_runs
        .mark_failed
        .call_args
        .kwargs
    )

    assert failed_call["run_id"] == run_id

    assert (
        failed_call["error_summary"]
        == "RuntimeError: Database write failed"
    )

    # Création du run puis statut failed.
    assert unit_of_work.commit.call_count == 2
    
    assert (
    failed_call["records_received"]
    == 1
    )

    assert (
        failed_call["records_succeeded"]
        == 0
    )

    assert (
        failed_call["records_failed"]
        == 1
    )


def test_ingest_marks_run_failed_when_link_persistence_fails() -> None:
    source_id = uuid4()
    run_id = uuid4()

    unit_of_work = _build_unit_of_work()

    (
        unit_of_work
        .sync_states
        .get_by_source_id
        .return_value
    ) = None

    (
        unit_of_work
        .ingestion_runs
        .create
        .return_value
    ) = run_id

    (
        unit_of_work
        .raw_payloads
        .save_many_ignore_existing
        .return_value
    ) = _build_batch_result(
        source_id=source_id,
        external_record_id="CVE-2026-0002",
        payload_hash="c" * 64,
        inserted=True,
    )

    (
        unit_of_work
        .ingestion_run_payloads
        .link_many_ignore_existing
        .side_effect
    ) = RuntimeError(
        "Observation write failed"
    )

    (
        unit_of_work
        .ingestion_runs
        .mark_failed
        .return_value
    ) = True

    connector = Mock()

    connector.fetch.return_value = FetchResult(
        records=[
            FetchedRecord(
                external_record_id="CVE-2026-0002",
                payload={
                    "id": "CVE-2026-0002",
                },
            )
        ],
    )

    payload_hasher = Mock()
    payload_hasher.hash.return_value = (
        "c" * 64
    )

    service = IngestionService(
        unit_of_work=unit_of_work,
        connector=connector,
        payload_hasher=payload_hasher,
    )

    with pytest.raises(
        RuntimeError,
        match="Observation write failed",
    ):
        service.ingest(
            source_id=source_id,
        )

    (
        unit_of_work
        .sync_states
        .upsert
        .assert_not_called()
    )

    (
        unit_of_work
        .ingestion_runs
        .mark_failed
        .assert_called_once()
    )

    # Le lot payload/liens n'a pas été commité.
    # Création du run puis statut failed.
    assert unit_of_work.commit.call_count == 2


def test_ingest_marks_run_failed_when_completion_update_fails() -> None:
    source_id = uuid4()
    run_id = uuid4()

    unit_of_work = _build_unit_of_work()

    (
        unit_of_work
        .sync_states
        .get_by_source_id
        .return_value
    ) = None

    (
        unit_of_work
        .ingestion_runs
        .create
        .return_value
    ) = run_id

    (
        unit_of_work
        .raw_payloads
        .save_many_ignore_existing
        .return_value
    ) = _build_batch_result(
        source_id=source_id,
        external_record_id="CVE-2026-0003",
        payload_hash="d" * 64,
        inserted=True,
    )

    _configure_link_result(
        unit_of_work
    )

    (
        unit_of_work
        .ingestion_runs
        .mark_completed
        .return_value
    ) = False

    (
        unit_of_work
        .ingestion_runs
        .mark_failed
        .return_value
    ) = True

    connector = Mock()

    connector.fetch.return_value = FetchResult(
        records=[
            FetchedRecord(
                external_record_id="CVE-2026-0003",
                payload={
                    "id": "CVE-2026-0003",
                },
            )
        ],
        next_cursor="cursor-003",
    )

    payload_hasher = Mock()
    payload_hasher.hash.return_value = (
        "d" * 64
    )

    service = IngestionService(
        unit_of_work=unit_of_work,
        connector=connector,
        payload_hasher=payload_hasher,
    )

    with pytest.raises(
        RuntimeError,
        match="Unable to complete ingestion run",
    ):
        service.ingest(
            source_id=source_id,
        )

    connector.fetch.assert_called_once_with(
        cursor=None,
        state_metadata=None,
    )

    (
        unit_of_work
        .ingestion_runs
        .mark_failed
        .assert_called_once()
    )

    failed_call = (
        unit_of_work
        .ingestion_runs
        .mark_failed
        .call_args
        .kwargs
    )

    assert failed_call["run_id"] == run_id

    assert (
        failed_call["error_summary"]
        == (
            "RuntimeError: Unable to "
            "complete ingestion run"
        )
    )

    # 1. création du run
    # 2. persistance batch
    # 3. statut failed
    assert unit_of_work.commit.call_count == 3
    
    assert (
    failed_call["records_received"]
    == 1
    )

    assert (
        failed_call["records_succeeded"]
        == 1
    )

    assert (
        failed_call["records_failed"]
        == 0
)


def test_ingest_raises_critical_error_when_mark_failed_fails() -> None:
    source_id = uuid4()
    run_id = uuid4()

    unit_of_work = _build_unit_of_work()

    (
        unit_of_work
        .sync_states
        .get_by_source_id
        .return_value
    ) = None

    (
        unit_of_work
        .ingestion_runs
        .create
        .return_value
    ) = run_id

    (
        unit_of_work
        .ingestion_runs
        .mark_failed
        .return_value
    ) = False

    connector = Mock()

    connector.fetch.side_effect = RuntimeError(
        "Connector unavailable"
    )

    payload_hasher = Mock()

    service = IngestionService(
        unit_of_work=unit_of_work,
        connector=connector,
        payload_hasher=payload_hasher,
    )

    with pytest.raises(
        RuntimeError,
        match=(
            "Unable to mark ingestion "
            "run as failed"
        ),
    ) as exc_info:
        service.ingest(
            source_id=source_id,
        )

    connector.fetch.assert_called_once_with(
        cursor=None,
        state_metadata=None,
    )

    assert isinstance(
        exc_info.value.__cause__,
        RuntimeError,
    )

    assert (
        str(exc_info.value.__cause__)
        == "Connector unavailable"
    )

    (
        unit_of_work
        .ingestion_runs
        .mark_failed
        .assert_called_once()
    )

    # Seul le commit initial du run a réussi.
    assert unit_of_work.commit.call_count == 1