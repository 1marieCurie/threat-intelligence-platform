from unittest.mock import Mock
from uuid import uuid4
import pytest

from application.ports.outbound.ingestion_connector import (
    FetchedRecord,
    FetchResult,
)
from application.ports.outbound.sync_state_repository import (
    SyncStateData,
)
from application.services.ingestion_service import (
    IngestionService,
)


def test_ingest_persists_new_records_and_commits() -> None:
    source_id = uuid4()
    run_id = uuid4()

    unit_of_work = Mock()
    unit_of_work.__enter__ = Mock(
        return_value=unit_of_work
    )
    unit_of_work.__exit__ = Mock(
        return_value=None
    )

    unit_of_work.sync_states.get_by_source_id.return_value = (
        SyncStateData(
            source_id=source_id,
            cursor="cursor-001",
        )
    )

    unit_of_work.ingestion_runs.create.return_value = (
        run_id
    )
    unit_of_work.raw_payloads.exists_by_identity.return_value = (
        False
    )
    unit_of_work.ingestion_runs.mark_completed.return_value = (
        True
    )

    connector = Mock()
    connector.fetch.return_value = FetchResult(
        records=[
            FetchedRecord(
                external_record_id="CVE-2026-0001",
                payload={
                    "id": "CVE-2026-0001",
                },
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
    payload_hasher.hash.return_value = "a" * 64

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
    )

    unit_of_work.raw_payloads.save.assert_called_once()
    unit_of_work.sync_states.upsert.assert_called_once()
    unit_of_work.ingestion_runs.mark_completed.assert_called_once()
    assert unit_of_work.commit.call_count == 2
    
    assert result.run_id == run_id
    assert result.records_received == 1
    assert result.records_persisted == 1
    assert result.records_skipped == 0
    assert result.status == "completed"
    
def test_ingest_skips_existing_payload() -> None:
    source_id = uuid4()
    run_id = uuid4()

    unit_of_work = Mock()
    unit_of_work.__enter__ = Mock(
        return_value=unit_of_work
    )
    unit_of_work.__exit__ = Mock(
        return_value=None
    )

    unit_of_work.sync_states.get_by_source_id.return_value = (
        None
    )
    unit_of_work.ingestion_runs.create.return_value = (
        run_id
    )
    unit_of_work.raw_payloads.exists_by_identity.return_value = (
        True
    )
    unit_of_work.ingestion_runs.mark_completed.return_value = (
        True
    )

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
        next_cursor="cursor-001",
    )

    payload_hasher = Mock()
    payload_hasher.hash.return_value = "b" * 64

    service = IngestionService(
        unit_of_work=unit_of_work,
        connector=connector,
        payload_hasher=payload_hasher,
    )

    result = service.ingest(
        source_id=source_id,
    )

    connector.fetch.assert_called_once_with(
        cursor=None,
    )

    unit_of_work.raw_payloads.save.assert_not_called()
    assert unit_of_work.commit.call_count == 2

    assert result.records_received == 1
    assert result.records_persisted == 0
    assert result.records_skipped == 1

def test_ingest_marks_run_failed_when_connector_fails() -> None:
    source_id = uuid4()
    run_id = uuid4()

    unit_of_work = Mock()
    unit_of_work.__enter__ = Mock(
        return_value=unit_of_work
    )
    unit_of_work.__exit__ = Mock(
        return_value=None
    )

    unit_of_work.sync_states.get_by_source_id.return_value = (
        None
    )

    unit_of_work.ingestion_runs.create.return_value = (
        run_id
    )

    unit_of_work.ingestion_runs.mark_failed.return_value = (
        True
    )

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

    unit_of_work.ingestion_runs.mark_failed.assert_called_once()

    failed_call = (
        unit_of_work.ingestion_runs
        .mark_failed.call_args.kwargs
    )

    assert failed_call["run_id"] == run_id
    assert (
        failed_call["error_summary"]
        == "RuntimeError: Connector unavailable"
    )

    unit_of_work.sync_states.upsert.assert_not_called()
    unit_of_work.raw_payloads.save.assert_not_called()

    assert unit_of_work.commit.call_count == 2

def test_ingest_marks_run_failed_when_persistence_fails() -> None:
    source_id = uuid4()
    run_id = uuid4()

    unit_of_work = Mock()
    unit_of_work.__enter__ = Mock(
        return_value=unit_of_work
    )
    unit_of_work.__exit__ = Mock(
        return_value=None
    )

    unit_of_work.sync_states.get_by_source_id.return_value = (
        None
    )

    unit_of_work.ingestion_runs.create.return_value = (
        run_id
    )

    unit_of_work.raw_payloads.exists_by_identity.return_value = (
        False
    )

    unit_of_work.raw_payloads.save.side_effect = (
        RuntimeError("Database write failed")
    )

    unit_of_work.ingestion_runs.mark_failed.return_value = (
        True
    )

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
    payload_hasher.hash.return_value = "c" * 64

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

    unit_of_work.sync_states.upsert.assert_not_called()

    unit_of_work.ingestion_runs.mark_failed.assert_called_once()

    failed_call = (
        unit_of_work.ingestion_runs
        .mark_failed.call_args.kwargs
    )

    assert failed_call["run_id"] == run_id
    assert (
        failed_call["error_summary"]
        == "RuntimeError: Database write failed"
    )
    
def test_ingest_marks_run_failed_when_completion_update_fails() -> None:
    source_id = uuid4()
    run_id = uuid4()

    unit_of_work = Mock()
    unit_of_work.__enter__ = Mock(
        return_value=unit_of_work
    )
    unit_of_work.__exit__ = Mock(
        return_value=None
    )

    unit_of_work.sync_states.get_by_source_id.return_value = None
    unit_of_work.ingestion_runs.create.return_value = run_id
    unit_of_work.raw_payloads.exists_by_identity.return_value = False
    unit_of_work.ingestion_runs.mark_completed.return_value = False
    unit_of_work.ingestion_runs.mark_failed.return_value = True

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
    payload_hasher.hash.return_value = "d" * 64

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

    unit_of_work.ingestion_runs.mark_failed.assert_called_once()

    failed_call = (
        unit_of_work.ingestion_runs
        .mark_failed.call_args.kwargs
    )

    assert failed_call["run_id"] == run_id
    assert (
        failed_call["error_summary"]
        == "RuntimeError: Unable to complete ingestion run"
    )

    assert unit_of_work.commit.call_count == 2
    
def test_ingest_raises_critical_error_when_mark_failed_fails() -> None:
    source_id = uuid4()
    run_id = uuid4()

    unit_of_work = Mock()
    unit_of_work.__enter__ = Mock(
        return_value=unit_of_work
    )
    unit_of_work.__exit__ = Mock(
        return_value=None
    )

    unit_of_work.sync_states.get_by_source_id.return_value = None
    unit_of_work.ingestion_runs.create.return_value = run_id
    unit_of_work.ingestion_runs.mark_failed.return_value = False

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
        match="Unable to mark ingestion run as failed",
    ) as exc_info:
        service.ingest(
            source_id=source_id,
        )

    assert isinstance(
        exc_info.value.__cause__,
        RuntimeError,
    )

    assert str(
        exc_info.value.__cause__
    ) == "Connector unavailable"

    unit_of_work.ingestion_runs.mark_failed.assert_called_once()

    # Seul le commit initial du run "running" a réussi.
    assert unit_of_work.commit.call_count == 1
    
