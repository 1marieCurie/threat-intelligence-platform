from __future__ import annotations

import bz2
import json
from pathlib import Path
from typing import Any

import requests

from infrastructure.adapters.outbound.phishtank_connector import (
    PhishTankConnector,
    PhishTankConnectorError,
)


class FakeResponse:
    def __init__(
        self,
        *,
        content: bytes = b"",
        headers: dict[str, str] | None = None,
        status_code: int = 200,
    ) -> None:
        self.content = content
        self.headers = (
            headers
            if headers is not None
            else {}
        )
        self.status_code = (
            status_code
        )

    def raise_for_status(
        self,
    ) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(
                f"HTTP {self.status_code}"
            )

    def iter_content(
        self,
        chunk_size: int,
    ):
        for index in range(
            0,
            len(self.content),
            chunk_size,
        ):
            yield self.content[
                index:
                index + chunk_size
            ]

    def __enter__(
        self,
    ) -> FakeResponse:
        return self

    def __exit__(
        self,
        exc_type,
        exc_value,
        traceback,
    ) -> bool:
        return False


class FakeSession:
    def __init__(
        self,
        *,
        head_response: FakeResponse | None = None,
        get_response: FakeResponse | None = None,
        head_error: Exception | None = None,
    ) -> None:
        self.head_response = (
            head_response
            if head_response is not None
            else FakeResponse()
        )

        self.get_response = (
            get_response
            if get_response is not None
            else FakeResponse()
        )

        self.head_error = (
            head_error
        )

        self.head_calls: list[
            dict[str, Any]
        ] = []

        self.get_calls: list[
            dict[str, Any]
        ] = []

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

        if self.head_error is not None:
            raise self.head_error

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

        return self.get_response


def _compressed_snapshot(
) -> bytes:
    return bz2.compress(
        json.dumps(
            [
                {
                    "phish_id": 9477391,
                    "url": (
                        "https://example.invalid/"
                        "login"
                    ),
                }
            ]
        ).encode(
            "utf-8"
        )
    )


def _build_connector(
    tmp_path: Path,
    *,
    app_key: str,
    session: FakeSession,
) -> PhishTankConnector:
    return PhishTankConnector(
        storage_directory=(
            tmp_path
            / "phishtank"
        ),
        app_key=app_key,
        session=session,  # type: ignore[arg-type]
    )


def test_connector_keeps_secret_only_in_http_url(
    tmp_path: Path,
) -> None:
    secret = "private-app-key"

    session = FakeSession(
        head_response=FakeResponse(
            headers={
                "ETag": '"etag-1"',
            }
        ),
        get_response=FakeResponse(
            content=_compressed_snapshot(),
            headers={
                "ETag": '"etag-1"',
            },
        ),
    )

    connector = _build_connector(
        tmp_path,
        app_key=secret,
        session=session,
    )

    metadata = (
        connector.download_if_updated()
    )

    assert secret in (
        connector.download_url
    )

    assert (
        connector.canonical_source_url
        == connector.PUBLIC_DOWNLOAD_URL
    )

    assert secret not in repr(
        connector
    )

    serialized_metadata = json.dumps(
        metadata
    )

    serialized_state = (
        connector.state_path.read_text(
            encoding="utf-8"
        )
    )

    assert secret not in (
        serialized_metadata
    )

    assert secret not in (
        serialized_state
    )

    assert metadata[
        "source_url"
    ] == connector.PUBLIC_DOWNLOAD_URL

    assert metadata[
        "download_url"
    ] == connector.PUBLIC_DOWNLOAD_URL

    assert session.head_calls[0][
        "url"
    ] == connector.download_url

    assert session.get_calls[0][
        "url"
    ] == connector.download_url


def test_connector_sanitizes_legacy_state(
    tmp_path: Path,
) -> None:
    secret = "legacy-app-key"

    session = FakeSession()

    connector = _build_connector(
        tmp_path,
        app_key=secret,
        session=session,
    )

    secret_url = (
        "https://data.phishtank.com/data/"
        f"{secret}/online-valid.json.bz2"
    )

    connector.state_path.write_text(
        json.dumps(
            {
                "source": "PHISHTANK",
                "app_key": secret,
                "download_url": secret_url,
                "source_url": secret_url,
                "nested": {
                    "request_url": (
                        secret_url
                    ),
                    "access_token": (
                        secret
                    ),
                },
            }
        ),
        encoding="utf-8",
    )

    state = (
        connector.get_local_state()
    )

    serialized_state = json.dumps(
        state
    )

    assert secret not in (
        serialized_state
    )

    assert "app_key" not in state

    assert state[
        "download_url"
    ] == connector.PUBLIC_DOWNLOAD_URL

    assert state[
        "source_url"
    ] == connector.PUBLIC_DOWNLOAD_URL

    assert state["nested"][
        "request_url"
    ] == connector.PUBLIC_DOWNLOAD_URL

    assert (
        "access_token"
        not in state["nested"]
    )


def test_local_fallback_does_not_restore_secret(
    tmp_path: Path,
) -> None:
    secret = "fallback-app-key"

    session = FakeSession(
        head_error=(
            requests.ConnectionError(
                "HEAD unavailable"
            )
        )
    )

    connector = _build_connector(
        tmp_path,
        app_key=secret,
        session=session,
    )

    connector.dump_path.write_bytes(
        _compressed_snapshot()
    )

    connector.state_path.write_text(
        json.dumps(
            {
                "source": "PHISHTANK",
                "etag": '"legacy-etag"',
                "download_url": (
                    "https://data.phishtank.com/"
                    f"data/{secret}/"
                    "online-valid.json.bz2"
                ),
                "app_key": secret,
            }
        ),
        encoding="utf-8",
    )

    metadata = (
        connector.download_if_updated()
    )

    serialized_metadata = json.dumps(
        metadata
    )

    assert secret not in (
        serialized_metadata
    )

    assert metadata[
        "downloaded"
    ] is False

    assert metadata[
        "used_local_snapshot"
    ] is True

    assert metadata[
        "head_request_failed"
    ] is True

    assert metadata[
        "download_url"
    ] == connector.PUBLIC_DOWNLOAD_URL


def test_connector_error_does_not_expose_app_key(
    tmp_path: Path,
) -> None:
    secret = "error-app-key"

    session = FakeSession(
        head_error=(
            requests.ConnectionError(
                f"Failed URL containing {secret}"
            )
        )
    )

    connector = _build_connector(
        tmp_path,
        app_key=secret,
        session=session,
    )

    try:
        connector.get_remote_metadata()

    except PhishTankConnectorError as error:
        assert secret not in str(
            error
        )

    else:
        raise AssertionError(
            "PhishTankConnectorError was expected"
        )