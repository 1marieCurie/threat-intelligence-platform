from __future__ import annotations

import json
from typing import Any

import pytest

from application.ports.outbound.ingestion_connector import (
    FetchResult,
)
from infrastructure.adapters.outbound.urlhaus.urlhaus_ingestion_connector import (
    URLhausIngestionConnector,
)


class FakeURLhausConnector:
    def __init__(
        self,
        *,
        response: dict[str, Any] | None = None,
        source_url: str = (
            "https://urlhaus-api.abuse.ch/v1"
        ),
    ) -> None:
        self.response = (
            response
            if response is not None
            else {
                "query_status": "ok",
                "urls": [],
            }
        )

        self.canonical_source_url = (
            source_url
        )

        self.calls: list[
            dict[str, Any]
        ] = []

    def fetch_recent_urls(
        self,
        limit: int | None = None,
    ) -> dict[str, Any]:
        self.calls.append(
            {
                "limit": limit,
            }
        )

        return self.response


def build_record(
    urlhaus_id: Any = 3_886_331,
) -> dict[str, Any]:
    return {
        "id": urlhaus_id,
        "urlhaus_reference": (
            "https://urlhaus.abuse.ch/"
            "url/3886331/"
        ),
        "url": (
            "http://malicious.example/"
            "payload"
        ),
        "url_status": "online",
        "host": "malicious.example",
        "date_added": (
            "2026-07-14 10:21:37 UTC"
        ),
        "threat": "malware_download",
        "tags": [
            "elf",
            "mirai",
        ],
    }


def build_adapter(
    *,
    response: dict[str, Any] | None = None,
    limit: int | None = None,
    source_url: str = (
        "https://urlhaus-api.abuse.ch/v1"
    ),
) -> tuple[
    URLhausIngestionConnector,
    FakeURLhausConnector,
]:
    connector = FakeURLhausConnector(
        response=response,
        source_url=source_url,
    )

    adapter = URLhausIngestionConnector(
        connector=connector,
        limit=limit,
    )

    return (
        adapter,
        connector,
    )


def test_constructor_rejects_none_connector(
) -> None:
    with pytest.raises(
        ValueError,
        match="must not be None",
    ):
        URLhausIngestionConnector(
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
    connector = FakeURLhausConnector()

    with pytest.raises(
        TypeError,
        match="limit must be an integer",
    ):
        URLhausIngestionConnector(
            connector=connector,
            limit=invalid_limit,
        )


@pytest.mark.parametrize(
    "invalid_limit",
    [
        0,
        -1,
        1_001,
    ],
)
def test_constructor_rejects_invalid_limit_value(
    invalid_limit: int,
) -> None:
    connector = FakeURLhausConnector()

    with pytest.raises(
        ValueError,
        match="between 1 and 1000",
    ):
        URLhausIngestionConnector(
            connector=connector,
            limit=invalid_limit,
        )


def test_fetch_rejects_cursor_before_provider_call(
) -> None:
    adapter, connector = (
        build_adapter()
    )

    with pytest.raises(
        ValueError,
        match="does not support cursors",
    ):
        adapter.fetch(
            cursor="unexpected"
        )

    assert connector.calls == []


def test_fetch_maps_recent_records(
) -> None:
    raw_record = build_record()

    adapter, connector = build_adapter(
        response={
            "query_status": "ok",
            "urls": [
                raw_record,
            ],
        },
        limit=25,
    )

    result = adapter.fetch(
        cursor=None
    )

    assert isinstance(
        result,
        FetchResult,
    )

    assert connector.calls == [
        {
            "limit": 25,
        }
    ]

    assert len(
        result.records
    ) == 1

    fetched_record = (
        result.records[0]
    )

    assert (
        fetched_record.external_record_id
        == "3886331"
    )

    assert (
        fetched_record.payload
        is raw_record
    )

    assert fetched_record.source_url == (
        "https://urlhaus-api.abuse.ch/v1"
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


def test_fetch_normalizes_numeric_string_id(
) -> None:
    adapter, _ = build_adapter(
        response={
            "query_status": "ok",
            "urls": [
                build_record(
                    " 003886331 "
                ),
            ],
        }
    )

    result = adapter.fetch(
        cursor=None
    )

    assert (
        result.records[0]
        .external_record_id
        == "3886331"
    )


@pytest.mark.parametrize(
    "invalid_identifier",
    [
        None,
        True,
        False,
        0,
        -1,
        "",
        "invalid",
        1.5,
    ],
)
def test_fetch_rejects_invalid_identifier(
    invalid_identifier: Any,
) -> None:
    adapter, _ = build_adapter(
        response={
            "query_status": "ok",
            "urls": [
                build_record(
                    invalid_identifier
                ),
            ],
        }
    )

    with pytest.raises(
        ValueError,
        match=(
            "id must be a positive integer"
        ),
    ):
        adapter.fetch(
            cursor=None
        )


def test_fetch_rejects_duplicate_identifiers(
) -> None:
    adapter, _ = build_adapter(
        response={
            "query_status": "ok",
            "urls": [
                build_record(100),
                build_record("100"),
            ],
        }
    )

    with pytest.raises(
        ValueError,
        match="duplicate URLhaus identifier",
    ):
        adapter.fetch(
            cursor=None
        )


def test_fetch_returns_empty_result_for_no_results(
) -> None:
    adapter, _ = build_adapter(
        response={
            "query_status": "no_results",
        }
    )

    result = adapter.fetch(
        cursor=None
    )

    assert tuple(
        result.records
    ) == ()

    assert (
        result.metadata[
            "query_status"
        ]
        == "no_results"
    )

    assert (
        result.metadata[
            "records_count"
        ]
        == 0
    )


def test_fetch_rejects_invalid_response_root(
) -> None:
    connector = FakeURLhausConnector()

    connector.response = []  # type: ignore[assignment]

    adapter = URLhausIngestionConnector(
        connector=connector
    )

    with pytest.raises(
        TypeError,
        match="must be a dictionary",
    ):
        adapter.fetch(
            cursor=None
        )


@pytest.mark.parametrize(
    "response",
    [
        {},
        {
            "query_status": "unexpected",
        },
        {
            "query_status": None,
        },
    ],
)
def test_fetch_rejects_invalid_query_status(
    response: dict[str, Any],
) -> None:
    adapter, _ = build_adapter(
        response=response
    )

    with pytest.raises(
        ValueError,
        match="query_status",
    ):
        adapter.fetch(
            cursor=None
        )


def test_fetch_rejects_missing_urls_list(
) -> None:
    adapter, _ = build_adapter(
        response={
            "query_status": "ok",
        }
    )

    with pytest.raises(
        ValueError,
        match="'urls' must be a list",
    ):
        adapter.fetch(
            cursor=None
        )


def test_fetch_rejects_non_object_record(
) -> None:
    adapter, _ = build_adapter(
        response={
            "query_status": "ok",
            "urls": [
                "invalid-record",
            ],
        }
    )

    with pytest.raises(
        ValueError,
        match="expected an object",
    ):
        adapter.fetch(
            cursor=None
        )


def test_metadata_uses_security_allowlist(
) -> None:
    secret = "private-auth-key"

    adapter, _ = build_adapter(
        response={
            "query_status": "ok",
            "urls": [
                build_record(),
            ],
            "auth_key": secret,
            "provider_debug": {
                "token": secret,
            },
        }
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
        "auth_key"
        not in result.metadata
    )

    assert (
        "provider_debug"
        not in result.metadata
    )

    assert result.metadata == {
        "source": "urlhaus",
        "source_url": (
            "https://urlhaus-api.abuse.ch/v1"
        ),
        "collection_mode": (
            "recent_urls"
        ),
        "configured_limit": None,
        "records_count": 1,
        "query_status": "ok",
        "pagination_complete": True,
        "window_complete": True,
        "historical_complete": False,
    }


def test_fetch_does_not_mutate_state_metadata(
) -> None:
    previous_state = {
        "previous": "value",
    }

    adapter, _ = build_adapter()

    adapter.fetch(
        cursor=None,
        state_metadata=previous_state,
    )

    assert previous_state == {
        "previous": "value",
    }


@pytest.mark.parametrize(
    "unsafe_source_url",
    [
        (
            "https://user:password@"
            "urlhaus-api.abuse.ch/v1"
        ),
        (
            "https://urlhaus-api.abuse.ch/"
            "v1?auth_key=secret"
        ),
        (
            "https://urlhaus-api.abuse.ch/"
            "v1#secret"
        ),
    ],
)
def test_fetch_rejects_unsafe_source_url(
    unsafe_source_url: str,
) -> None:
    adapter, _ = build_adapter(
        source_url=unsafe_source_url
    )

    with pytest.raises(
        ValueError,
        match="must not contain credentials",
    ):
        adapter.fetch(
            cursor=None
        )