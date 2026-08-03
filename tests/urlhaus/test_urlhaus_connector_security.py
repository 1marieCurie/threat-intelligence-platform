from __future__ import annotations

from typing import Any

import pytest
import requests

from infrastructure.adapters.outbound.urlhaus_connector import (
    URLhausConnector,
    URLhausHTTPError,
    URLhausQueryError,
    URLhausResponseError,
)


class FakeResponse:
    def __init__(
        self,
        *,
        status_code: int = 200,
        json_data: Any = None,
        text: str = "",
        json_exception: Exception | None = None,
    ) -> None:
        self.status_code = status_code
        self._json_data = json_data
        self.text = text
        self._json_exception = (
            json_exception
        )

    def raise_for_status(
        self,
    ) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(
                f"HTTP {self.status_code}"
            )

    def json(
        self,
    ) -> Any:
        if self._json_exception is not None:
            raise self._json_exception

        return self._json_data


class FakeSession:
    def __init__(
        self,
        *,
        response: FakeResponse | None = None,
        get_exception: Exception | None = None,
    ) -> None:
        self.response = response
        self.get_exception = get_exception

    def get(
        self,
        url: str,
        *,
        headers: dict[str, str],
        timeout: float,
    ) -> FakeResponse:
        del url
        del headers
        del timeout

        if self.get_exception is not None:
            raise self.get_exception

        if self.response is None:
            raise AssertionError(
                "No response configured."
            )

        return self.response

    def post(
        self,
        url: str,
        *,
        headers: dict[str, str],
        data: dict[str, str],
        timeout: float,
    ) -> FakeResponse:
        del url
        del headers
        del data
        del timeout

        if self.response is None:
            raise AssertionError(
                "No response configured."
            )

        return self.response


def test_http_error_does_not_expose_response_body(
) -> None:
    sensitive_url = (
        "http://user:password@"
        "malicious.example/"
        "?access_token=secret-token"
    )

    connector = URLhausConnector(
        auth_key="private-auth-key",
        session=FakeSession(
            response=FakeResponse(
                status_code=500,
                text=sensitive_url,
            )
        ),  # type: ignore[arg-type]
    )

    with pytest.raises(
        URLhausHTTPError
    ) as captured_error:
        connector.fetch_recent_urls(
            limit=10
        )

    error_message = str(
        captured_error.value
    )

    assert "HTTP 500" in error_message
    assert sensitive_url not in error_message
    assert "secret-token" not in error_message
    assert "password" not in error_message


def test_invalid_json_does_not_expose_response_body(
) -> None:
    sensitive_body = (
        '{"url": "http://malicious.example/", '
        '"api_key": "private-key"}'
    )

    connector = URLhausConnector(
        auth_key="private-auth-key",
        session=FakeSession(
            response=FakeResponse(
                status_code=200,
                text=sensitive_body,
                json_exception=ValueError(
                    "invalid JSON"
                ),
            )
        ),  # type: ignore[arg-type]
    )

    with pytest.raises(
        URLhausResponseError
    ) as captured_error:
        connector.fetch_recent_urls(
            limit=10
        )

    error_message = str(
        captured_error.value
    )

    assert (
        error_message
        == "URLhaus returned invalid JSON."
    )

    assert sensitive_body not in error_message
    assert "private-key" not in error_message


def test_request_exception_does_not_expose_original_message(
) -> None:
    sensitive_message = (
        "connection failed for "
        "https://user:password@example.test/"
        "?token=private-token"
    )

    connector = URLhausConnector(
        auth_key="private-auth-key",
        session=FakeSession(
            get_exception=(
                requests.ConnectionError(
                    sensitive_message
                )
            )
        ),  # type: ignore[arg-type]
    )

    with pytest.raises(
        URLhausHTTPError
    ) as captured_error:
        connector.fetch_recent_urls(
            limit=10
        )

    error_message = str(
        captured_error.value
    )

    assert (
        error_message
        == "URLhaus GET request failed."
    )

    assert sensitive_message not in error_message
    assert "private-token" not in error_message
    assert "password" not in error_message


def test_unsafe_query_status_is_not_echoed(
) -> None:
    sensitive_status = (
        "http://malicious.example/"
        "?bearer_token=private-token"
    )

    connector = URLhausConnector(
        auth_key="private-auth-key",
        session=FakeSession(
            response=FakeResponse(
                json_data={
                    "query_status": (
                        sensitive_status
                    ),
                }
            )
        ),  # type: ignore[arg-type]
    )

    with pytest.raises(
        URLhausQueryError
    ) as captured_error:
        connector.fetch_recent_urls(
            limit=10
        )

    error_message = str(
        captured_error.value
    )

    assert (
        error_message
        == (
            "URLhaus query failed with "
            "an unsafe query status."
        )
    )

    assert sensitive_status not in error_message
    assert "private-token" not in error_message


@pytest.mark.parametrize(
    "unsafe_base_url",
    [
        (
            "https://user:password@"
            "urlhaus-api.abuse.ch/v1"
        ),
        (
            "https://urlhaus-api.abuse.ch/"
            "v1?api_key=private"
        ),
        (
            "https://urlhaus-api.abuse.ch/"
            "v1#private"
        ),
    ],
)
def test_connector_rejects_unsafe_base_url(
    unsafe_base_url: str,
) -> None:
    with pytest.raises(
        ValueError,
        match="must not contain credentials",
    ):
        URLhausConnector(
            auth_key="private-auth-key",
            base_url=unsafe_base_url,
            session=FakeSession(),  # type: ignore[arg-type]
        )