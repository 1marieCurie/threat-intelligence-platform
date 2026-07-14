from __future__ import annotations

from typing import Any, Dict, Optional

import pytest
import requests

from infrastructure.adapters.outbound.urlhaus_connector import (
    URLhausAuthenticationError,
    URLhausConnector,
    URLhausHTTPError,
    URLhausQueryError,
    URLhausResponseError,
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
        json_data: Any = None,
        text: str = "",
        json_exception: Optional[Exception] = None,
    ) -> None:
        self.status_code = status_code
        self._json_data = json_data
        self.text = text
        self._json_exception = json_exception

    def json(self) -> Any:
        if self._json_exception is not None:
            raise self._json_exception

        return self._json_data

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(
                f"HTTP {self.status_code}"
            )


class FakeSession(requests.Session):
    """
    Fake requests.Session recording GET and POST calls.
    """

    def __init__(
        self,
        *,
        get_response: Optional[FakeResponse] = None,
        post_response: Optional[FakeResponse] = None,
        get_exception: Optional[Exception] = None,
        post_exception: Optional[Exception] = None,
    ) -> None:
        super().__init__()
        self.get_response = get_response
        self.post_response = post_response
        self.get_exception = get_exception
        self.post_exception = post_exception

        self.get_calls: list[Dict[str, Any]] = []
        self.post_calls: list[Dict[str, Any]] = []

    def get(
        self,
        url: str,
        *,
        headers: Dict[str, str],
        timeout: float,
    ) -> FakeResponse:
        self.get_calls.append(
            {
                "url": url,
                "headers": headers,
                "timeout": timeout,
            }
        )

        if self.get_exception is not None:
            raise self.get_exception

        if self.get_response is None:
            raise AssertionError(
                "No fake GET response configured."
            )

        return self.get_response

    def post(
        self,
        url: str,
        *,
        headers: Dict[str, str],
        data: Dict[str, str],
        timeout: float,
    ) -> FakeResponse:
        self.post_calls.append(
            {
                "url": url,
                "headers": headers,
                "data": data,
                "timeout": timeout,
            }
        )

        if self.post_exception is not None:
            raise self.post_exception

        if self.post_response is None:
            raise AssertionError(
                "No fake POST response configured."
            )

        return self.post_response


# ============================================================
# Fixtures
# ============================================================


@pytest.fixture
def recent_urls_payload() -> Dict[str, Any]:
    return {
        "query_status": "ok",
        "urls": [
            {
                "id": 3886331,
                "urlhaus_reference": (
                    "https://urlhaus.abuse.ch/url/3886331/"
                ),
                "url": (
                    "http://zipper.rapidbranchzi.com/"
                    "main_mpsl"
                ),
                "url_status": "online",
                "host": "zipper.rapidbranchzi.com",
                "date_added": "2026-07-14 10:21:37 UTC",
                "threat": "malware_download",
                "blacklists": {
                    "spamhaus_dbl": "not listed",
                    "surbl": "not listed",
                },
                "reporter": "burger",
                "larted": "true",
                "tags": ["elf", "mirai"],
            }
        ],
    }


@pytest.fixture
def detailed_url_payload() -> Dict[str, Any]:
    return {
        "query_status": "ok",
        "id": 3886331,
        "urlhaus_reference": (
            "https://urlhaus.abuse.ch/url/3886331/"
        ),
        "url": (
            "http://zipper.rapidbranchzi.com/main_mpsl"
        ),
        "url_status": "online",
        "host": "zipper.rapidbranchzi.com",
        "date_added": "2026-07-14 10:21:37 UTC",
        "last_online": "2026-07-14 11:00:00 UTC",
        "threat": "malware_download",
        "blacklists": {
            "spamhaus_dbl": "not listed",
            "surbl": "not listed",
        },
        "reporter": "burger",
        "larted": "true",
        "takedown_time_seconds": None,
        "tags": ["elf", "mirai"],
        "payloads": [
            {
                "firstseen": "2026-07-14",
                "filename": "main_mpsl",
                "file_type": "elf",
                "response_size": "123456",
                "response_md5": (
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                ),
                "response_sha256": (
                    "b" * 64
                ),
                "signature": "Mirai",
            }
        ],
    }


@pytest.fixture
def no_results_payload() -> Dict[str, Any]:
    return {
        "query_status": "no_results",
    }


# ============================================================
# Initialization tests
# ============================================================


def test_init_accepts_explicit_auth_key() -> None:
    connector = URLhausConnector(
        auth_key="test-auth-key"
    )

    assert connector is not None


def test_init_reads_auth_key_from_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "URLHAUS_AUTH_KEY",
        "environment-auth-key",
    )

    connector = URLhausConnector()

    assert connector is not None


def test_init_rejects_missing_auth_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(
        "URLHAUS_AUTH_KEY",
        raising=False,
    )

    with pytest.raises(
        URLhausAuthenticationError,
        match="Auth-Key is required",
    ):
        URLhausConnector()


@pytest.mark.parametrize(
    "auth_key",
    [
        "",
        "   ",
    ],
)
def test_init_rejects_empty_auth_key(
    auth_key: str,
) -> None:
    with pytest.raises(
        URLhausAuthenticationError,
        match="must not be empty",
    ):
        URLhausConnector(auth_key=auth_key)


@pytest.mark.parametrize(
    "timeout",
    [
        0,
        -1,
        -0.5,
        "30",
        True,
        False
    ],
)
def test_init_rejects_invalid_timeout(
    timeout: Any,
) -> None:
    with pytest.raises(
        ValueError,
        match="timeout must be a positive number",
    ):
        URLhausConnector(
            auth_key="test-key",
            timeout=timeout,
        )


@pytest.mark.parametrize(
    "base_url",
    [
        "",
        "   ",
    ],
)
def test_init_rejects_empty_base_url(
    base_url: str,
) -> None:
    with pytest.raises(
        ValueError,
        match="base_url must not be empty",
    ):
        URLhausConnector(
            auth_key="test-key",
            base_url=base_url,
        )


# ============================================================
# Recent URLs tests
# ============================================================


def test_fetch_recent_urls_without_limit(
    recent_urls_payload: Dict[str, Any],
) -> None:
    session = FakeSession(
        get_response=FakeResponse(
            json_data=recent_urls_payload
        )
    )

    connector = URLhausConnector(
        auth_key="test-key",
        session=session,
    )

    result = connector.fetch_recent_urls()

    assert result == recent_urls_payload
    assert len(session.get_calls) == 1

    call = session.get_calls[0]

    assert call["url"] == (
        "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    )
    assert call["headers"]["Auth-Key"] == "test-key"
    assert call["headers"]["Accept"] == "application/json"
    assert call["timeout"] == 30.0


def test_fetch_recent_urls_with_limit(
    recent_urls_payload: Dict[str, Any],
) -> None:
    session = FakeSession(
        get_response=FakeResponse(
            json_data=recent_urls_payload
        )
    )

    connector = URLhausConnector(
        auth_key="test-key",
        session=session,
        timeout=12,
    )

    result = connector.fetch_recent_urls(limit=5)

    assert result["query_status"] == "ok"
    assert len(result["urls"]) == 1

    call = session.get_calls[0]

    assert call["url"] == (
        "https://urlhaus-api.abuse.ch/"
        "v1/urls/recent/limit/5/"
    )
    assert call["timeout"] == 12.0


@pytest.mark.parametrize(
    "limit",
    [
        0,
        -1,
        1001,
        1.5,
        "5",
        None,
        True,
    ],
)
def test_fetch_recent_urls_rejects_invalid_limit(
    limit: Any,
) -> None:
    connector = URLhausConnector(
        auth_key="test-key",
        session=FakeSession(),
    )

    if limit is None:
        # None is valid and means no explicit URL limit.
        return

    with pytest.raises(ValueError):
        connector.fetch_recent_urls(limit=limit)

def test_fetch_recent_urls_accepts_none_limit(
    recent_urls_payload: Dict[str, Any],
) -> None:
    session = FakeSession(
        get_response=FakeResponse(
            json_data=recent_urls_payload
        )
    )

    connector = URLhausConnector(
        auth_key="test-key",
        session=session,
    )

    result = connector.fetch_recent_urls(
        limit=None
    )

    assert result == recent_urls_payload

    assert session.get_calls[0]["url"] == (
        "https://urlhaus-api.abuse.ch/v1/urls/recent/"
    )

def test_fetch_recent_urls_accepts_boundary_limits(
    recent_urls_payload: Dict[str, Any],
) -> None:
    for limit in (1, 1000):
        session = FakeSession(
            get_response=FakeResponse(
                json_data=recent_urls_payload
            )
        )

        connector = URLhausConnector(
            auth_key="test-key",
            session=session,
        )

        connector.fetch_recent_urls(limit=limit)

        assert session.get_calls[0]["url"].endswith(
            f"/limit/{limit}/"
        )


def test_fetch_recent_urls_returns_no_results(
    no_results_payload: Dict[str, Any],
) -> None:
    session = FakeSession(
        get_response=FakeResponse(
            json_data=no_results_payload
        )
    )

    connector = URLhausConnector(
        auth_key="test-key",
        session=session,
    )

    result = connector.fetch_recent_urls(limit=5)

    assert result == {
        "query_status": "no_results",
    }


# ============================================================
# Detailed URL tests
# ============================================================


def test_fetch_url_information_posts_url(
    detailed_url_payload: Dict[str, Any],
) -> None:
    session = FakeSession(
        post_response=FakeResponse(
            json_data=detailed_url_payload
        )
    )

    connector = URLhausConnector(
        auth_key="test-key",
        session=session,
    )

    queried_url = (
        "http://zipper.rapidbranchzi.com/main_mpsl"
    )

    result = connector.fetch_url_information(
        queried_url
    )

    assert result["query_status"] == "ok"
    assert result["url"] == queried_url

    call = session.post_calls[0]

    assert call["url"] == (
        "https://urlhaus-api.abuse.ch/v1/url/"
    )
    assert call["data"] == {
        "url": queried_url,
    }


@pytest.mark.parametrize(
    "url",
    [
        "",
        "   ",
    ],
)
def test_fetch_url_information_rejects_empty_url(
    url: str,
) -> None:
    connector = URLhausConnector(
        auth_key="test-key",
        session=FakeSession(),
    )

    with pytest.raises(
        ValueError,
        match="url must not be empty",
    ):
        connector.fetch_url_information(url)


def test_fetch_url_information_rejects_non_string_url() -> None:
    connector = URLhausConnector(
        auth_key="test-key",
        session=FakeSession(),
    )

    with pytest.raises(
        TypeError,
        match="url must be a string",
    ):
        connector.fetch_url_information(123)  # type: ignore[arg-type]


def test_fetch_url_information_by_id_posts_urlhaus_id(
    detailed_url_payload: Dict[str, Any],
) -> None:
    session = FakeSession(
        post_response=FakeResponse(
            json_data=detailed_url_payload
        )
    )

    connector = URLhausConnector(
        auth_key="test-key",
        session=session,
    )

    result = connector.fetch_url_information_by_id(
        3886331
    )

    assert result["id"] == 3886331

    call = session.post_calls[0]

    assert call["url"] == (
        "https://urlhaus-api.abuse.ch/v1/urlid/"
    )
    assert call["data"] == {
        "urlid": "3886331",
    }


@pytest.mark.parametrize(
    "urlhaus_id",
    [
        "",
        "   ",
        "ABC123",
        "-1",
        None,
    ],
)
def test_fetch_url_information_by_id_rejects_invalid_id(
    urlhaus_id: Any,
) -> None:
    connector = URLhausConnector(
        auth_key="test-key",
        session=FakeSession(),
    )

    with pytest.raises(ValueError):
        connector.fetch_url_information_by_id(
            urlhaus_id
        )


# ============================================================
# Host tests
# ============================================================


@pytest.mark.parametrize(
    "host",
    [
        "example.com",
        "192.0.2.10",
        "2001:db8::10",
    ],
)
def test_fetch_host_information_posts_host(
    host: str,
) -> None:
    payload = {
        "query_status": "ok",
        "host": host,
        "urls": [],
    }

    session = FakeSession(
        post_response=FakeResponse(
            json_data=payload
        )
    )

    connector = URLhausConnector(
        auth_key="test-key",
        session=session,
    )

    result = connector.fetch_host_information(host)

    assert result["host"] == host

    call = session.post_calls[0]

    assert call["url"] == (
        "https://urlhaus-api.abuse.ch/v1/host/"
    )
    assert call["data"] == {
        "host": host,
    }


@pytest.mark.parametrize(
    "host",
    [
        "",
        "   ",
    ],
)
def test_fetch_host_information_rejects_empty_host(
    host: str,
) -> None:
    connector = URLhausConnector(
        auth_key="test-key",
        session=FakeSession(),
    )

    with pytest.raises(
        ValueError,
        match="host must not be empty",
    ):
        connector.fetch_host_information(host)


# ============================================================
# Payload tests
# ============================================================


def test_fetch_recent_payloads_with_limit() -> None:
    payload = {
        "query_status": "ok",
        "payloads": [],
    }

    session = FakeSession(
        get_response=FakeResponse(
            json_data=payload
        )
    )

    connector = URLhausConnector(
        auth_key="test-key",
        session=session,
    )

    result = connector.fetch_recent_payloads(
        limit=10
    )

    assert result == payload

    call = session.get_calls[0]

    assert call["url"] == (
        "https://urlhaus-api.abuse.ch/"
        "v1/payloads/recent/limit/10/"
    )


def test_fetch_payload_information_with_md5() -> None:
    md5_hash = "a" * 32

    payload = {
        "query_status": "ok",
        "md5_hash": md5_hash,
    }

    session = FakeSession(
        post_response=FakeResponse(
            json_data=payload
        )
    )

    connector = URLhausConnector(
        auth_key="test-key",
        session=session,
    )

    result = connector.fetch_payload_information(
        md5_hash=md5_hash.upper()
    )

    assert result["query_status"] == "ok"

    call = session.post_calls[0]

    assert call["data"] == {
        "md5_hash": md5_hash,
    }


def test_fetch_payload_information_with_sha256() -> None:
    sha256_hash = "b" * 64

    payload = {
        "query_status": "ok",
        "sha256_hash": sha256_hash,
    }

    session = FakeSession(
        post_response=FakeResponse(
            json_data=payload
        )
    )

    connector = URLhausConnector(
        auth_key="test-key",
        session=session,
    )

    connector.fetch_payload_information(
        sha256_hash=sha256_hash
    )

    call = session.post_calls[0]

    assert call["data"] == {
        "sha256_hash": sha256_hash,
    }


@pytest.mark.parametrize(
    "kwargs",
    [
        {},
        {
            "md5_hash": "a" * 32,
            "sha256_hash": "b" * 64,
        },
    ],
)
def test_fetch_payload_information_requires_exactly_one_hash(
    kwargs: Dict[str, str],
) -> None:
    connector = URLhausConnector(
        auth_key="test-key",
        session=FakeSession(),
    )

    with pytest.raises(
        ValueError,
        match="exactly one",
    ):
        connector.fetch_payload_information(**kwargs)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("md5_hash", "a" * 31),
        ("md5_hash", "z" * 32),
        ("sha256_hash", "b" * 63),
        ("sha256_hash", "x" * 64),
    ],
)
def test_fetch_payload_information_rejects_invalid_hash(
    field_name: str,
    value: str,
) -> None:
    connector = URLhausConnector(
        auth_key="test-key",
        session=FakeSession(),
    )

    kwargs = {
        field_name: value,
    }

    with pytest.raises(ValueError):
        connector.fetch_payload_information(**kwargs)


# ============================================================
# HTTP and response errors
# ============================================================


def test_get_timeout_is_wrapped() -> None:
    session = FakeSession(
        get_exception=requests.Timeout(
            "request timed out"
        )
    )

    connector = URLhausConnector(
        auth_key="test-key",
        session=session,
    )

    with pytest.raises(
        URLhausHTTPError,
        match="timed out",
    ):
        connector.fetch_recent_urls(limit=5)


def test_post_timeout_is_wrapped() -> None:
    session = FakeSession(
        post_exception=requests.Timeout(
            "request timed out"
        )
    )

    connector = URLhausConnector(
        auth_key="test-key",
        session=session,
    )

    with pytest.raises(
        URLhausHTTPError,
        match="timed out",
    ):
        connector.fetch_host_information(
            "example.com"
        )


def test_get_request_exception_is_wrapped() -> None:
    session = FakeSession(
        get_exception=requests.ConnectionError(
            "connection failed"
        )
    )

    connector = URLhausConnector(
        auth_key="test-key",
        session=session,
    )

    with pytest.raises(
        URLhausHTTPError,
        match="GET request failed",
    ):
        connector.fetch_recent_urls(limit=5)


@pytest.mark.parametrize(
    "status_code",
    [
        401,
        403,
    ],
)
def test_authentication_error_for_rejected_key(
    status_code: int,
) -> None:
    session = FakeSession(
        get_response=FakeResponse(
            status_code=status_code,
            text="Invalid Auth-Key",
        )
    )

    connector = URLhausConnector(
        auth_key="invalid-key",
        session=session,
    )

    with pytest.raises(
        URLhausAuthenticationError,
        match="rejected",
    ):
        connector.fetch_recent_urls(limit=5)


def test_http_error_contains_status_and_body() -> None:
    session = FakeSession(
        get_response=FakeResponse(
            status_code=500,
            text="Internal server error",
        )
    )

    connector = URLhausConnector(
        auth_key="test-key",
        session=session,
    )

    with pytest.raises(
        URLhausHTTPError,
        match="HTTP 500",
    ):
        connector.fetch_recent_urls(limit=5)


def test_invalid_json_is_rejected() -> None:
    session = FakeSession(
        get_response=FakeResponse(
            status_code=200,
            text="<html>not json</html>",
            json_exception=ValueError(
                "Invalid JSON"
            ),
        )
    )

    connector = URLhausConnector(
        auth_key="test-key",
        session=session,
    )

    with pytest.raises(
        URLhausResponseError,
        match="invalid JSON",
    ):
        connector.fetch_recent_urls(limit=5)


@pytest.mark.parametrize(
    "payload",
    [
        [],
        "not-an-object",
        123,
        None,
    ],
)
def test_non_dictionary_json_root_is_rejected(
    payload: Any,
) -> None:
    session = FakeSession(
        get_response=FakeResponse(
            json_data=payload
        )
    )

    connector = URLhausConnector(
        auth_key="test-key",
        session=session,
    )

    with pytest.raises(
        URLhausResponseError,
        match="root must be a JSON object",
    ):
        connector.fetch_recent_urls(limit=5)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {
            "query_status": None,
        },
        {
            "query_status": 123,
        },
    ],
)
def test_missing_or_invalid_query_status_is_rejected(
    payload: Dict[str, Any],
) -> None:
    session = FakeSession(
        get_response=FakeResponse(
            json_data=payload
        )
    )

    connector = URLhausConnector(
        auth_key="test-key",
        session=session,
    )

    with pytest.raises(
        URLhausResponseError,
        match="query_status",
    ):
        connector.fetch_recent_urls(limit=5)


@pytest.mark.parametrize(
    "query_status",
    [
        "invalid_auth_key",
        "illegal_hash",
        "http_post_expected",
        "unexpected_status",
    ],
)
def test_unsuccessful_query_status_is_rejected(
    query_status: str,
) -> None:
    session = FakeSession(
        get_response=FakeResponse(
            json_data={
                "query_status": query_status,
            }
        )
    )

    connector = URLhausConnector(
        auth_key="test-key",
        session=session,
    )

    with pytest.raises(
        URLhausQueryError,
        match=query_status,
    ):
        connector.fetch_recent_urls(limit=5)


def test_base_url_trailing_slash_is_normalized(
    recent_urls_payload: Dict[str, Any],
) -> None:
    session = FakeSession(
        get_response=FakeResponse(
            json_data=recent_urls_payload
        )
    )

    connector = URLhausConnector(
        auth_key="test-key",
        session=session,
        base_url="https://example.test/v1/",
    )

    connector.fetch_recent_urls(limit=5)

    assert session.get_calls[0]["url"] == (
        "https://example.test/v1/urls/recent/limit/5/"
    )