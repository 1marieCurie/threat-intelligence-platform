from unittest.mock import Mock

import pytest
import requests

from infrastructure.adapters.outbound.cisa_connector import (
    CISAConnector,
)


def _build_session() -> Mock:
    session = Mock(
        spec=requests.Session,
    )

    session.headers = {}

    return session


def test_constructor_configures_session_headers() -> None:
    session = _build_session()

    CISAConnector(
        session=session,
        timeout=15,
    )

    assert session.headers == {
        "Accept": "application/json",
        "User-Agent": (
            "Threat-Intelligence-Engine/1.0"
        ),
    }


@pytest.mark.parametrize(
    ("invalid_timeout", "expected_error"),
    [
        (True, TypeError),
        ("30", TypeError),
        (None, TypeError),
        (0, ValueError),
        (-1, ValueError),
    ],
)
def test_constructor_rejects_invalid_timeout(
    invalid_timeout: object,
    expected_error: type[Exception],
) -> None:
    with pytest.raises(
        expected_error,
        match="timeout",
    ):
        CISAConnector(
            timeout=invalid_timeout,  # type: ignore[arg-type]
        )


def test_fetch_returns_json_object() -> None:
    session = _build_session()
    response = Mock(
        spec=requests.Response,
    )

    expected_payload = {
        "count": 1,
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-0001",
            }
        ],
    }

    response.json.return_value = expected_payload
    session.get.return_value = response

    connector = CISAConnector(
        session=session,
        timeout=12.5,
    )

    result = connector.fetch()

    session.get.assert_called_once_with(
        CISAConnector.KEV_URL,
        timeout=12.5,
    )

    response.raise_for_status.assert_called_once_with()

    assert result is expected_payload


def test_fetch_propagates_http_error() -> None:
    session = _build_session()
    response = Mock(
        spec=requests.Response,
    )

    response.raise_for_status.side_effect = (
        requests.HTTPError(
            "CISA unavailable"
        )
    )

    session.get.return_value = response

    connector = CISAConnector(
        session=session,
    )

    with pytest.raises(
        requests.HTTPError,
        match="CISA unavailable",
    ):
        connector.fetch()

    response.json.assert_not_called()


def test_fetch_rejects_invalid_json() -> None:
    session = _build_session()
    response = Mock(
        spec=requests.Response,
    )

    response.json.side_effect = ValueError(
        "Malformed JSON"
    )

    session.get.return_value = response

    connector = CISAConnector(
        session=session,
    )

    with pytest.raises(
        ValueError,
        match="invalid JSON",
    ):
        connector.fetch()


@pytest.mark.parametrize(
    "invalid_payload",
    [
        None,
        [],
        "invalid",
        123,
    ],
)
def test_fetch_rejects_non_object_payload(
    invalid_payload: object,
) -> None:
    session = _build_session()
    response = Mock(
        spec=requests.Response,
    )

    response.json.return_value = invalid_payload
    session.get.return_value = response

    connector = CISAConnector(
        session=session,
    )

    with pytest.raises(
        ValueError,
        match="expected a JSON object",
    ):
        connector.fetch()


def test_default_session_has_retry_policy() -> None:
    session = CISAConnector._build_session()

    adapter = session.get_adapter(
        "https://"
    )

    assert adapter.max_retries.total == 3
    assert adapter.max_retries.connect == 3
    assert adapter.max_retries.read == 3
    assert adapter.max_retries.status == 3

    assert adapter.max_retries.allowed_methods == (
        frozenset(
            {
                "GET",
            }
        )
    )