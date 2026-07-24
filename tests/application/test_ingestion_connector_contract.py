from application.ports.outbound.ingestion_connector import (
    FetchedRecord,
    FetchResult,
)


def test_fetch_result_contains_records_and_cursor() -> None:
    record = FetchedRecord(
        external_record_id="CVE-2026-0001",
        payload={
            "id": "CVE-2026-0001",
        },
        http_status=200,
    )

    result = FetchResult(
        records=[record],
        next_cursor="page-2",
        metadata={
            "page": 1,
        },
        connector_version="1.0.0",
    )

    assert len(result.records) == 1
    assert result.records[0].external_record_id == "CVE-2026-0001"
    assert result.next_cursor == "page-2"
    assert result.metadata == {
        "page": 1,
    }