from __future__ import annotations

import json
from typing import Any

import pytest

from application.ports.outbound.ingestion_connector import (
    FetchResult,
)
from infrastructure.adapters.outbound.phishtank.phishtank_ingestion_connector import (
    PhishTankIngestionConnector,
)


class FakePhishTankSnapshotConnector:
    def __init__(
        self,
        *,
        records: list[
            dict[str, Any]
        ] | None = None,
        metadata: dict[
            str,
            Any
        ] | None = None,
    ) -> None:
        self.canonical_source_url = (
            "https://data.phishtank.com/data/"
            "online-valid.json.bz2"
        )

        self.records = (
            records
            if records is not None
            else []
        )

        self.metadata = (
            metadata
            if metadata is not None
            else {}
        )

        self.download_calls: list[
            dict[str, Any]
        ] = []

        self.read_calls: list[
            dict[str, Any]
        ] = []

    def download_if_updated(
        self,
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        self.download_calls.append(
            {
                "force": force,
            }
        )

        return dict(
            self.metadata
        )

    def read_local_records(
        self,
        *,
        limit: int | None = None,
    ) -> list[dict[str, Any]]:
        self.read_calls.append(
            {
                "limit": limit,
            }
        )

        if limit is None:
            return list(
                self.records
            )

        return list(
            self.records[:limit]
        )


def build_record(
    phish_id: int | str = 9477391,
) -> dict[str, Any]:
    return {
        "phish_id": phish_id,
        "url": (
            "https://example.invalid/login"
        ),
        "verified": "yes",
        "online": "yes",
        "details": [],
    }


def build_adapter(
    *,
    records: list[
        dict[str, Any]
    ] | None = None,
    metadata: dict[
        str,
        Any
    ] | None = None,
    limit: int | None = None,
    force_download: bool = False,
) -> tuple[
    PhishTankIngestionConnector,
    FakePhishTankSnapshotConnector,
]:
    connector = (
        FakePhishTankSnapshotConnector(
            records=records,
            metadata=metadata,
        )
    )

    adapter = (
        PhishTankIngestionConnector(
            connector=connector,
            limit=limit,
            force_download=(
                force_download
            ),
        )
    )

    return adapter, connector


def test_constructor_rejects_none_connector(
) -> None:
    with pytest.raises(
        ValueError,
        match=(
            "connector must not be None"
        ),
    ):
        PhishTankIngestionConnector(
            connector=None,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "invalid_limit",
    [
        True,
        "10",
        1.5,
    ],
)
def test_constructor_rejects_invalid_limit_type(
    invalid_limit: Any,
) -> None:
    connector = (
        FakePhishTankSnapshotConnector()
    )

    with pytest.raises(
        TypeError,
        match=(
            "limit must be an integer"
        ),
    ):
        PhishTankIngestionConnector(
            connector=connector,
            limit=invalid_limit,
        )


def test_constructor_rejects_negative_limit(
) -> None:
    connector = (
        FakePhishTankSnapshotConnector()
    )

    with pytest.raises(
        ValueError,
        match=(
            "greater than or equal to zero"
        ),
    ):
        PhishTankIngestionConnector(
            connector=connector,
            limit=-1,
        )


def test_constructor_rejects_invalid_force_download(
) -> None:
    connector = (
        FakePhishTankSnapshotConnector()
    )

    with pytest.raises(
        TypeError,
        match=(
            "force_download must be a boolean"
        ),
    ):
        PhishTankIngestionConnector(
            connector=connector,
            force_download=1,  # type: ignore[arg-type]
        )


def test_fetch_rejects_cursor_before_connector_call(
) -> None:
    adapter, connector = (
        build_adapter()
    )

    with pytest.raises(
        ValueError,
        match=(
            "do not support cursors"
        ),
    ):
        adapter.fetch(
            cursor="unexpected-cursor"
        )

    assert (
        connector.download_calls
        == []
    )

    assert (
        connector.read_calls
        == []
    )


def test_fetch_maps_records_to_fetch_result(
) -> None:
    raw_record = build_record()

    adapter, connector = build_adapter(
        records=[
            raw_record,
        ],
        metadata={
            "downloaded": True,
            "used_local_snapshot": False,
            "etag": '"etag-1"',
            "content_length": 1024,
            "downloaded_at": (
                "2026-07-31T12:00:00+00:00"
            ),
        },
    )

    result = adapter.fetch(
        cursor=None
    )

    assert isinstance(
        result,
        FetchResult,
    )

    assert len(
        result.records
    ) == 1

    fetched_record = (
        result.records[0]
    )

    assert (
        fetched_record.external_record_id
        == "9477391"
    )

    assert (
        fetched_record.payload
        is raw_record
    )

    assert (
        fetched_record.source_url
        == connector.canonical_source_url
    )

    assert (
        fetched_record.fetched_at
        is not None
    )

    assert (
        fetched_record.fetched_at.tzinfo
        is not None
    )

    assert (
        fetched_record.http_status
        == 200
    )

    assert result.next_cursor is None

    assert (
        result.connector_version
        == "1.0.0"
    )


def test_fetch_forwards_configuration(
) -> None:
    adapter, connector = (
        build_adapter(
            records=[
                build_record(),
            ],
            limit=10,
            force_download=True,
        )
    )

    adapter.fetch(
        cursor=None
    )

    assert (
        connector.download_calls
        == [
            {
                "force": True,
            }
        ]
    )

    assert (
        connector.read_calls
        == [
            {
                "limit": 10,
            }
        ]
    )


def test_bounded_fetch_is_marked_incomplete(
) -> None:
    adapter, _ = build_adapter(
        records=[
            build_record(),
        ],
        limit=1,
    )

    result = adapter.fetch(
        cursor=None
    )

    assert (
        result.metadata[
            "snapshot_complete"
        ]
        is False
    )

    assert (
        result.metadata[
            "configured_limit"
        ]
        == 1
    )

    assert (
        result.metadata[
            "pagination_complete"
        ]
        is True
    )


def test_unbounded_fetch_is_complete(
) -> None:
    adapter, _ = build_adapter(
        records=[
            build_record(),
        ],
    )

    result = adapter.fetch(
        cursor=None
    )

    assert (
        result.metadata[
            "snapshot_complete"
        ]
        is True
    )


def test_local_snapshot_has_no_http_status(
) -> None:
    adapter, _ = build_adapter(
        records=[
            build_record(),
        ],
        metadata={
            "downloaded": False,
            "used_local_snapshot": True,
        },
    )

    result = adapter.fetch(
        cursor=None
    )

    assert (
        result.records[0].http_status
        is None
    )

    assert (
        result.metadata[
            "used_local_snapshot"
        ]
        is True
    )


@pytest.mark.parametrize(
    "invalid_phish_id",
    [
        None,
        True,
        0,
        -1,
        "",
        "invalid",
        1.5,
    ],
)
def test_fetch_rejects_invalid_phish_id(
    invalid_phish_id: Any,
) -> None:
    adapter, _ = build_adapter(
        records=[
            build_record(
                invalid_phish_id
            ),
        ]
    )

    with pytest.raises(
        ValueError,
        match=(
            "phish_id must be a positive integer"
        ),
    ):
        adapter.fetch(
            cursor=None
        )


def test_fetch_normalizes_numeric_string_id(
) -> None:
    adapter, _ = build_adapter(
        records=[
            build_record(
                " 009477391 "
            ),
        ]
    )

    result = adapter.fetch(
        cursor=None
    )

    assert (
        result.records[0]
        .external_record_id
        == "9477391"
    )


def test_fetch_rejects_duplicate_ids(
) -> None:
    adapter, _ = build_adapter(
        records=[
            build_record(100),
            build_record("100"),
        ]
    )

    with pytest.raises(
        ValueError,
        match=(
            "duplicate phish identifier"
        ),
    ):
        adapter.fetch(
            cursor=None
        )


def test_metadata_uses_security_allowlist(
) -> None:
    secret = "private-app-key"

    adapter, connector = build_adapter(
        records=[
            build_record(),
        ],
        metadata={
            "downloaded": True,
            "etag": '"etag-1"',
            "download_url": (
                "https://data.phishtank.com/"
                f"data/{secret}/"
                "online-valid.json.bz2"
            ),
            "app_key": secret,
            "dump_path": (
                "C:/private/data/"
                "online-valid.json.bz2"
            ),
        },
    )

    result = adapter.fetch(
        cursor=None
    )

    serialized_metadata = json.dumps(
        result.metadata
    )

    assert (
        secret
        not in serialized_metadata
    )

    assert (
        "dump_path"
        not in result.metadata
    )

    assert (
        "app_key"
        not in result.metadata
    )

    assert (
        "download_url"
        not in result.metadata
    )

    assert (
        result.metadata[
            "source_url"
        ]
        == connector.canonical_source_url
    )


def test_fetch_does_not_mutate_state_metadata(
) -> None:
    previous_state = {
        "etag": '"old-etag"',
    }

    adapter, _ = build_adapter()

    adapter.fetch(
        cursor=None,
        state_metadata=previous_state,
    )

    assert previous_state == {
        "etag": '"old-etag"',
    }