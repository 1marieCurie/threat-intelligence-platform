from __future__ import annotations

import bz2
import json
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, cast

import pytest
import requests

from infrastructure.adapters.outbound.phishtank_connector import (
    PhishTankConnector,
    PhishTankConnectorError,
)


# ============================================================
# Fake HTTP objects
# ============================================================


class FakeResponse:
    """
    Minimal fake requests.Response used by unit tests.
    """

    def __init__(
        self,
        *,
        status_code: int = 200,
        headers: Optional[Dict[str, str]] = None,
        content: bytes = b"",
        request_exception: Optional[
            requests.RequestException
        ] = None,
    ) -> None:
        self.status_code = status_code
        self.headers = headers or {}
        self.content = content
        self.request_exception = request_exception

    def raise_for_status(self) -> None:
        if self.request_exception is not None:
            raise self.request_exception

        if self.status_code >= 400:
            raise requests.HTTPError(
                f"HTTP {self.status_code}"
            )

    def iter_content(
        self,
        chunk_size: int = 8192,
    ) -> Iterable[bytes]:
        for index in range(
            0,
            len(self.content),
            chunk_size,
        ):
            yield self.content[
                index:index + chunk_size
            ]

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(
        self,
        exc_type,
        exc_value,
        traceback,
    ) -> bool:
        return False


class FakeSession(requests.Session):
    """
    Fake HTTP session recording HEAD and GET calls.
    """

    def __init__(
        self,
        *,
        head_response: Optional[FakeResponse] = None,
        get_response: Optional[FakeResponse] = None,
        head_exception: Optional[
            requests.RequestException
        ] = None,
        get_exception: Optional[
            requests.RequestException
        ] = None,
    ) -> None:
        super().__init__()
        self.head_response = (
            head_response or FakeResponse()
        )
        self.get_response = (
            get_response or FakeResponse()
        )

        self.head_exception = head_exception
        self.get_exception = get_exception

        self.head_calls: list[dict[str, Any]] = []
        self.get_calls: list[dict[str, Any]] = []

    def head(
        self,
        url: str,
        **kwargs: Any,
    ) -> FakeResponse:
        self.head_calls.append(
            {
                "url": url,
                **kwargs,
            }
        )

        if self.head_exception is not None:
            raise self.head_exception

        return self.head_response

    def get(
        self,
        url: str,
        **kwargs: Any,
    ) -> FakeResponse:
        self.get_calls.append(
            {
                "url": url,
                **kwargs,
            }
        )

        if self.get_exception is not None:
            raise self.get_exception

        return self.get_response


# ============================================================
# Test helpers
# ============================================================


def build_raw_records() -> list[dict[str, Any]]:
    return [
        {
            "phish_id": 9477391,
            "url": (
                "https://fake-login.example.invalid/"
                "account/verify"
            ),
            "phish_detail_url": (
                "https://www.phishtank.com/"
                "phish_detail.php?phish_id=9477391"
            ),
            "submission_time": (
                "2026-07-13T11:03:01+00:00"
            ),
            "verified": "yes",
            "verification_time": (
                "2026-07-13T11:52:26+00:00"
            ),
            "online": "yes",
            "details": [
                {
                    "ip_address": "192.0.2.10",
                    "cidr_block": "192.0.2.0/24",
                    "announcing_network": "64500",
                    "rir": "arin",
                    "country": "MA",
                    "detail_time": (
                        "2026-07-13T11:12:10+00:00"
                    ),
                }
            ],
            "target": "Other",
        },
        {
            "phish_id": 9477387,
            "url": (
                "https://allegro-security."
                "example.invalid/verification"
            ),
            "phish_detail_url": (
                "https://www.phishtank.com/"
                "phish_detail.php?phish_id=9477387"
            ),
            "submission_time": (
                "2026-07-13T10:59:59+00:00"
            ),
            "verified": "yes",
            "verification_time": (
                "2026-07-13T11:03:40+00:00"
            ),
            "online": "yes",
            "details": [],
            "target": "Allegro",
        },
    ]


def compress_json_payload(
    payload: Any,
) -> bytes:
    serialized = json.dumps(
        payload,
        ensure_ascii=False,
    ).encode("utf-8")

    return bz2.compress(serialized)


def write_compressed_dump(
    path: Path,
    payload: Any,
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_bytes(
        compress_json_payload(payload)
    )


def write_state(
    path: Path,
    state: dict[str, Any],
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        json.dumps(
            state,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )


def create_connector(
    tmp_path: Path,
    *,
    session: Optional[FakeSession] = None,
    app_key: Optional[str] = None,
    timeout: float = 30.0,
    user_agent: str = (
        "threat-intelligence-engine-tests/1.0"
    ),
) -> PhishTankConnector:
    return PhishTankConnector(
        storage_directory=tmp_path / "phishtank",
        app_key=app_key,
        timeout=timeout,
        user_agent=user_agent,
        session=session,
    )


# ============================================================
# Initialization and URL tests
# ============================================================


def test_connector_creates_storage_directory(
    tmp_path: Path,
) -> None:
    connector = create_connector(tmp_path)

    assert connector.storage_directory.exists()
    assert connector.storage_directory.is_dir()


def test_connector_uses_public_download_url_without_key(
    tmp_path: Path,
) -> None:
    connector = create_connector(tmp_path)

    assert connector.download_url == (
        "https://data.phishtank.com/data/"
        "online-valid.json.bz2"
    )


def test_connector_builds_download_url_with_app_key(
    tmp_path: Path,
) -> None:
    connector = create_connector(
        tmp_path,
        app_key="test-app-key",
    )

    assert connector.download_url == (
        "https://data.phishtank.com/data/"
        "test-app-key/online-valid.json.bz2"
    )


def test_connector_trims_app_key(
    tmp_path: Path,
) -> None:
    connector = create_connector(
        tmp_path,
        app_key="  test-app-key  ",
    )

    assert connector.app_key == "test-app-key"


def test_empty_app_key_uses_public_url(
    tmp_path: Path,
) -> None:
    connector = create_connector(
        tmp_path,
        app_key="   ",
    )

    assert connector.app_key is None
    assert connector.download_url == (
        connector.PUBLIC_DOWNLOAD_URL
    )


@pytest.mark.parametrize(
    "invalid_timeout",
    [
        0,
        -1,
        -0.5,
    ],
)
def test_connector_rejects_invalid_timeout(
    tmp_path: Path,
    invalid_timeout: float,
) -> None:
    with pytest.raises(
        ValueError,
        match="timeout must be greater than zero",
    ):
        create_connector(
            tmp_path,
            timeout=invalid_timeout,
        )


@pytest.mark.parametrize(
    "invalid_user_agent",
    [
        "",
        " ",
        "\t",
        "\n",
    ],
)
def test_connector_rejects_empty_user_agent(
    tmp_path: Path,
    invalid_user_agent: str,
) -> None:
    with pytest.raises(
        ValueError,
        match="user_agent must not be empty",
    ):
        create_connector(
            tmp_path,
            user_agent=invalid_user_agent,
        )


# ============================================================
# HTTP metadata tests
# ============================================================


def test_get_remote_metadata_returns_headers(
    tmp_path: Path,
) -> None:
    session = FakeSession(
        head_response=FakeResponse(
            headers={
                "ETag": '"etag-123"',
                "Last-Modified": (
                    "Mon, 13 Jul 2026 12:23:00 GMT"
                ),
                "Content-Length": "2840000",
            }
        )
    )

    connector = create_connector(
        tmp_path,
        session=session,
    )

    metadata = connector.get_remote_metadata()

    assert metadata == {
        "etag": '"etag-123"',
        "last_modified": (
            "Mon, 13 Jul 2026 12:23:00 GMT"
        ),
        "content_length": 2840000,
    }


def test_get_remote_metadata_sends_expected_request(
    tmp_path: Path,
) -> None:
    session = FakeSession(
        head_response=FakeResponse()
    )

    connector = create_connector(
        tmp_path,
        session=session,
        user_agent="custom-agent/1.0",
    )

    connector.get_remote_metadata()

    assert len(session.head_calls) == 1

    call = session.head_calls[0]

    assert call["url"] == connector.download_url
    assert call["timeout"] == 30.0
    assert call["allow_redirects"] is True
    assert (
        call["headers"]["User-Agent"]
        == "custom-agent/1.0"
    )


def test_get_remote_metadata_handles_missing_headers(
    tmp_path: Path,
) -> None:
    session = FakeSession(
        head_response=FakeResponse(headers={})
    )

    connector = create_connector(
        tmp_path,
        session=session,
    )

    metadata = connector.get_remote_metadata()

    assert metadata["etag"] is None
    assert metadata["last_modified"] is None
    assert metadata["content_length"] is None


@pytest.mark.parametrize(
    "invalid_content_length",
    [
        "",
        "invalid",
        "-1",
    ],
)
def test_get_remote_metadata_ignores_invalid_content_length(
    tmp_path: Path,
    invalid_content_length: str,
) -> None:
    session = FakeSession(
        head_response=FakeResponse(
            headers={
                "Content-Length": invalid_content_length,
            }
        )
    )

    connector = create_connector(
        tmp_path,
        session=session,
    )

    metadata = connector.get_remote_metadata()

    assert metadata["content_length"] is None


def test_get_remote_metadata_wraps_network_error(
    tmp_path: Path,
) -> None:
    session = FakeSession(
        head_exception=requests.ConnectionError(
            "network unavailable"
        )
    )

    connector = create_connector(
        tmp_path,
        session=session,
    )

    with pytest.raises(
        PhishTankConnectorError,
        match="Unable to retrieve PhishTank",
    ):
        connector.get_remote_metadata()


def test_get_remote_metadata_wraps_http_error(
    tmp_path: Path,
) -> None:
    session = FakeSession(
        head_response=FakeResponse(
            status_code=503
        )
    )

    connector = create_connector(
        tmp_path,
        session=session,
    )

    with pytest.raises(
        PhishTankConnectorError,
        match="Unable to retrieve PhishTank",
    ):
        connector.get_remote_metadata()


# ============================================================
# Local dump reading tests
# ============================================================


def test_read_local_records_returns_all_records(
    tmp_path: Path,
) -> None:
    connector = create_connector(tmp_path)
    raw_records = build_raw_records()

    write_compressed_dump(
        connector.dump_path,
        raw_records,
    )

    records = connector.read_local_records()

    assert records == raw_records
    assert len(records) == 2


def test_read_local_records_applies_limit(
    tmp_path: Path,
) -> None:
    connector = create_connector(tmp_path)

    write_compressed_dump(
        connector.dump_path,
        build_raw_records(),
    )

    records = connector.read_local_records(
        limit=1
    )

    assert len(records) == 1
    assert records[0]["phish_id"] == 9477391


def test_read_local_records_accepts_zero_limit(
    tmp_path: Path,
) -> None:
    connector = create_connector(tmp_path)

    write_compressed_dump(
        connector.dump_path,
        build_raw_records(),
    )

    records = connector.read_local_records(
        limit=0
    )

    assert records == []


def test_read_local_records_rejects_negative_limit(
    tmp_path: Path,
) -> None:
    connector = create_connector(tmp_path)

    with pytest.raises(
        ValueError,
        match="limit must be greater than or equal to zero",
    ):
        connector.read_local_records(
            limit=-1
        )


def test_read_local_records_rejects_missing_dump(
    tmp_path: Path,
) -> None:
    connector = create_connector(tmp_path)

    with pytest.raises(
        PhishTankConnectorError,
        match="local PhishTank dump does not exist",
    ):
        connector.read_local_records()


def test_read_local_records_rejects_invalid_bz2(
    tmp_path: Path,
) -> None:
    connector = create_connector(tmp_path)

    connector.dump_path.write_bytes(
        b"not-a-valid-bz2-file"
    )

    with pytest.raises(
        PhishTankConnectorError,
        match="Unable to read the local PhishTank",
    ):
        connector.read_local_records()


def test_read_local_records_rejects_invalid_json(
    tmp_path: Path,
) -> None:
    connector = create_connector(tmp_path)

    connector.dump_path.write_bytes(
        bz2.compress(b"not valid json")
    )

    with pytest.raises(
        PhishTankConnectorError,
        match="Unable to read the local PhishTank",
    ):
        connector.read_local_records()


def test_read_local_records_rejects_non_list_payload(
    tmp_path: Path,
) -> None:
    connector = create_connector(tmp_path)

    write_compressed_dump(
        connector.dump_path,
        {
            "phish_id": 1,
        },
    )

    with pytest.raises(
        PhishTankConnectorError,
        match="JSON payload must be a list",
    ):
        connector.read_local_records()


def test_read_local_records_rejects_non_dictionary_item(
    tmp_path: Path,
) -> None:
    connector = create_connector(tmp_path)

    write_compressed_dump(
        connector.dump_path,
        [
            build_raw_records()[0],
            "invalid-record",
        ],
    )

    with pytest.raises(
        PhishTankConnectorError,
        match="index 1",
    ):
        connector.read_local_records()


# ============================================================
# Download tests
# ============================================================


def test_download_if_updated_downloads_when_dump_is_missing(
    tmp_path: Path,
) -> None:
    raw_records = build_raw_records()
    compressed_payload = compress_json_payload(
        raw_records
    )

    session = FakeSession(
        head_response=FakeResponse(
            headers={
                "ETag": '"new-etag"',
                "Last-Modified": (
                    "Mon, 13 Jul 2026 12:23:00 GMT"
                ),
                "Content-Length": str(
                    len(compressed_payload)
                ),
            }
        ),
        get_response=FakeResponse(
            headers={
                "ETag": '"new-etag"',
                "Last-Modified": (
                    "Mon, 13 Jul 2026 12:23:00 GMT"
                ),
                "Content-Length": str(
                    len(compressed_payload)
                ),
            },
            content=compressed_payload,
        ),
    )

    connector = create_connector(
        tmp_path,
        session=session,
    )

    metadata = connector.download_if_updated()

    assert metadata["downloaded"] is True
    assert metadata["used_local_snapshot"] is False
    assert metadata["etag"] == '"new-etag"'

    assert connector.dump_path.exists()
    assert connector.state_path.exists()

    assert len(session.head_calls) == 1
    assert len(session.get_calls) == 1

    assert (
        connector.read_local_records()
        == raw_records
    )


def test_download_if_updated_skips_unchanged_etag(
    tmp_path: Path,
) -> None:
    session = FakeSession(
        head_response=FakeResponse(
            headers={
                "ETag": '"same-etag"',
            }
        )
    )

    connector = create_connector(
        tmp_path,
        session=session,
    )

    write_compressed_dump(
        connector.dump_path,
        build_raw_records(),
    )

    write_state(
        connector.state_path,
        {
            "source": "PHISHTANK",
            "etag": '"same-etag"',
            "downloaded_at": (
                "2026-07-13T13:45:47+00:00"
            ),
        },
    )

    metadata = connector.download_if_updated()

    assert metadata["downloaded"] is False
    assert metadata["used_local_snapshot"] is True
    assert metadata["etag"] == '"same-etag"'

    assert len(session.head_calls) == 1
    assert len(session.get_calls) == 0


def test_download_if_updated_downloads_when_etag_changes(
    tmp_path: Path,
) -> None:
    new_records = [
        {
            "phish_id": 9999999,
            "url": (
                "https://new.example.invalid/login"
            ),
        }
    ]

    compressed_payload = compress_json_payload(
        new_records
    )

    session = FakeSession(
        head_response=FakeResponse(
            headers={
                "ETag": '"new-etag"',
            }
        ),
        get_response=FakeResponse(
            headers={
                "ETag": '"new-etag"',
            },
            content=compressed_payload,
        ),
    )

    connector = create_connector(
        tmp_path,
        session=session,
    )

    write_compressed_dump(
        connector.dump_path,
        build_raw_records(),
    )

    write_state(
        connector.state_path,
        {
            "source": "PHISHTANK",
            "etag": '"old-etag"',
        },
    )

    metadata = connector.download_if_updated()

    assert metadata["downloaded"] is True
    assert metadata["etag"] == '"new-etag"'
    assert len(session.get_calls) == 1

    records = connector.read_local_records()

    assert records == new_records


def test_download_if_updated_force_downloads_even_if_etag_same(
    tmp_path: Path,
) -> None:
    compressed_payload = compress_json_payload(
        build_raw_records()
    )

    session = FakeSession(
        head_response=FakeResponse(
            headers={
                "ETag": '"same-etag"',
            }
        ),
        get_response=FakeResponse(
            headers={
                "ETag": '"same-etag"',
            },
            content=compressed_payload,
        ),
    )

    connector = create_connector(
        tmp_path,
        session=session,
    )

    write_compressed_dump(
        connector.dump_path,
        build_raw_records(),
    )

    write_state(
        connector.state_path,
        {
            "etag": '"same-etag"',
        },
    )

    metadata = connector.download_if_updated(
        force=True
    )

    assert metadata["downloaded"] is True
    assert len(session.get_calls) == 1


def test_download_if_updated_uses_local_snapshot_when_head_fails(
    tmp_path: Path,
) -> None:
    session = FakeSession(
        head_exception=requests.ConnectionError(
            "HEAD unavailable"
        )
    )

    connector = create_connector(
        tmp_path,
        session=session,
    )

    write_compressed_dump(
        connector.dump_path,
        build_raw_records(),
    )

    write_state(
        connector.state_path,
        {
            "source": "PHISHTANK",
            "etag": '"local-etag"',
        },
    )

    metadata = connector.download_if_updated()

    assert metadata["downloaded"] is False
    assert metadata["used_local_snapshot"] is True
    assert metadata["head_request_failed"] is True
    assert metadata["etag"] == '"local-etag"'
    assert len(session.get_calls) == 0


def test_download_if_updated_downloads_when_head_fails_and_no_dump(
    tmp_path: Path,
) -> None:
    compressed_payload = compress_json_payload(
        build_raw_records()
    )

    session = FakeSession(
        head_exception=requests.ConnectionError(
            "HEAD unavailable"
        ),
        get_response=FakeResponse(
            headers={
                "ETag": '"download-etag"',
            },
            content=compressed_payload,
        ),
    )

    connector = create_connector(
        tmp_path,
        session=session,
    )

    metadata = connector.download_if_updated()

    assert metadata["downloaded"] is True
    assert connector.dump_path.exists()
    assert len(session.get_calls) == 1


def test_download_failure_does_not_replace_existing_dump(
    tmp_path: Path,
) -> None:
    original_records = build_raw_records()

    session = FakeSession(
        head_response=FakeResponse(
            headers={
                "ETag": '"new-etag"',
            }
        ),
        get_exception=requests.ConnectionError(
            "download unavailable"
        ),
    )

    connector = create_connector(
        tmp_path,
        session=session,
    )

    write_compressed_dump(
        connector.dump_path,
        original_records,
    )

    write_state(
        connector.state_path,
        {
            "etag": '"old-etag"',
        },
    )

    with pytest.raises(
        PhishTankConnectorError,
        match="Unable to download",
    ):
        connector.download_if_updated()

    assert (
        connector.read_local_records()
        == original_records
    )


def test_invalid_download_is_rejected_and_temporary_file_removed(
    tmp_path: Path,
) -> None:
    session = FakeSession(
        head_response=FakeResponse(
            headers={
                "ETag": '"new-etag"',
            }
        ),
        get_response=FakeResponse(
            headers={
                "ETag": '"new-etag"',
            },
            content=b"invalid-bz2-content",
        ),
    )

    connector = create_connector(
        tmp_path,
        session=session,
    )

    with pytest.raises(
        PhishTankConnectorError,
        match="not a valid BZ2 JSON snapshot",
    ):
        connector.download_if_updated()

    temporary_path = connector.dump_path.with_suffix(
        connector.dump_path.suffix + ".tmp"
    )

    assert not connector.dump_path.exists()
    assert not temporary_path.exists()


def test_download_rejects_empty_file(
    tmp_path: Path,
) -> None:
    session = FakeSession(
        head_response=FakeResponse(
            headers={
                "ETag": '"empty-etag"',
            }
        ),
        get_response=FakeResponse(
            content=b"",
        ),
    )

    connector = create_connector(
        tmp_path,
        session=session,
    )

    with pytest.raises(
        PhishTankConnectorError,
        match="downloaded PhishTank file is empty",
    ):
        connector.download_if_updated()


def test_download_rejects_non_list_json_payload(
    tmp_path: Path,
) -> None:
    compressed_payload = compress_json_payload(
        {
            "unexpected": "object",
        }
    )

    session = FakeSession(
        head_response=FakeResponse(
            headers={
                "ETag": '"object-etag"',
            }
        ),
        get_response=FakeResponse(
            content=compressed_payload,
        ),
    )

    connector = create_connector(
        tmp_path,
        session=session,
    )

    with pytest.raises(
        PhishTankConnectorError,
        match="JSON payload must be a list",
    ):
        connector.download_if_updated()


# ============================================================
# Synchronization state tests
# ============================================================


def test_get_local_state_returns_empty_dictionary_when_absent(
    tmp_path: Path,
) -> None:
    connector = create_connector(tmp_path)

    assert connector.get_local_state() == {}


def test_save_and_load_state(
    tmp_path: Path,
) -> None:
    connector = create_connector(tmp_path)

    state = {
        "source": "PHISHTANK",
        "etag": '"etag-123"',
        "record_count": 10,
    }

    connector._save_state(state)

    assert connector.get_local_state() == state


def test_load_state_rejects_invalid_json(
    tmp_path: Path,
) -> None:
    connector = create_connector(tmp_path)

    connector.state_path.write_text(
        "not-valid-json",
        encoding="utf-8",
    )

    with pytest.raises(
        PhishTankConnectorError,
        match="Unable to read the PhishTank",
    ):
        connector.get_local_state()


def test_load_state_rejects_non_dictionary_json(
    tmp_path: Path,
) -> None:
    connector = create_connector(tmp_path)

    connector.state_path.write_text(
        json.dumps(
            [
                {
                    "etag": '"etag-123"',
                }
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        PhishTankConnectorError,
        match="state must be a JSON object",
    ):
        connector.get_local_state()


# ============================================================
# fetch_raw orchestration tests
# ============================================================


def test_fetch_raw_downloads_then_reads_records(
    tmp_path: Path,
) -> None:
    compressed_payload = compress_json_payload(
        build_raw_records()
    )

    session = FakeSession(
        head_response=FakeResponse(
            headers={
                "ETag": '"etag-123"',
            }
        ),
        get_response=FakeResponse(
            headers={
                "ETag": '"etag-123"',
            },
            content=compressed_payload,
        ),
    )

    connector = create_connector(
        tmp_path,
        session=session,
    )

    records = connector.fetch_raw(
        limit=1
    )

    assert len(records) == 1
    assert records[0]["phish_id"] == 9477391


def test_fetch_raw_forwards_force_download(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connector = create_connector(tmp_path)

    captured: dict[str, Any] = {}

    def fake_download_if_updated(
        *,
        force: bool = False,
    ) -> dict[str, Any]:
        captured["force"] = force

        return {
            "downloaded": False,
        }

    def fake_read_local_records(
        *,
        limit: Optional[int] = None,
    ) -> list[dict[str, Any]]:
        captured["limit"] = limit

        return [
            {
                "phish_id": 1,
            }
        ]

    monkeypatch.setattr(
        connector,
        "download_if_updated",
        fake_download_if_updated,
    )

    monkeypatch.setattr(
        connector,
        "read_local_records",
        fake_read_local_records,
    )

    result = connector.fetch_raw(
        force_download=True,
        limit=5,
    )

    assert captured["force"] is True
    assert captured["limit"] == 5
    assert result == [
        {
            "phish_id": 1,
        }
    ]