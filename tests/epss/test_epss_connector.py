from __future__ import annotations

from datetime import date
from unittest.mock import Mock

import pytest
import requests

from application.models.epss_snapshot import (
    EPSSSnapshot,
)
from application.ports.outbound.epss_provider import (
    EPSSProviderError,
    EPSSProviderUnavailableError,
    InvalidEPSSResponseError,
)
from infrastructure.adapters.outbound.epss_connector import (
    EPSSConnector,
)


def _build_record(
    *,
    cve_id: str = "CVE-2021-44228",
    score: object = "0.950000000",
    percentile: object = "0.990000000",
    score_date: object = "2026-07-30",
) -> dict[str, object]:
    return {
        "cve": cve_id,
        "epss": score,
        "percentile": percentile,
        "date": score_date,
    }


def _build_payload(
    *records: dict[str, object],
    version: object = "2026.07",
) -> dict[str, object]:
    return {
        "status": "OK",
        "status-code": 200,
        "version": version,
        "total": len(records),
        "data": list(records),
    }


def _build_response(
    *,
    payload: object,
) -> Mock:
    response = Mock(
        spec=requests.Response,
    )

    response.raise_for_status.return_value = None
    response.json.return_value = payload

    return response


def _build_session(
    *responses: Mock,
) -> Mock:
    session = Mock(
        spec=requests.Session,
    )

    # EPSSConnector configure les en-têtes lors
    # de son initialisation.
    session.headers = {}

    if len(responses) == 1:
        session.get.return_value = responses[0]

    elif responses:
        session.get.side_effect = list(
            responses
        )

    return session


def test_constructor_configures_http_headers() -> None:
    session = _build_session()

    EPSSConnector(
        session=session,
    )

    assert session.headers == {
        "Accept": "application/json",
        "User-Agent": (
            "Threat-Intelligence-Engine"
        ),
    }


@pytest.mark.parametrize(
    "invalid_timeout",
    [
        True,
        "10",
        None,
    ],
)
def test_constructor_rejects_invalid_timeout_type(
    invalid_timeout: object,
) -> None:
    session = _build_session()

    with pytest.raises(
        TypeError,
        match="timeout must be a number",
    ):
        EPSSConnector(
            session=session,
            timeout=invalid_timeout,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "invalid_timeout",
    [
        0,
        -1,
        float("nan"),
        float("inf"),
        float("-inf"),
    ],
)
def test_constructor_rejects_invalid_timeout_value(
    invalid_timeout: float,
) -> None:
    session = _build_session()

    with pytest.raises(
        ValueError,
        match=(
            "timeout must be a finite "
            "positive number"
        ),
    ):
        EPSSConnector(
            session=session,
            timeout=invalid_timeout,
        )


def test_fetch_by_cve_ids_returns_typed_snapshots() -> None:
    response = _build_response(
        payload=_build_payload(
            _build_record(
                cve_id="CVE-2021-44228",
                score="0.95",
                percentile="0.99",
            ),
            _build_record(
                cve_id="CVE-2024-4577",
                score="0.80",
                percentile="0.90",
            ),
        )
    )

    session = _build_session(
        response
    )

    connector = EPSSConnector(
        session=session,
    )

    result = connector.fetch_by_cve_ids(
        [
            " cve-2021-44228 ",
            "CVE-2024-4577",
            "CVE-2021-44228",
        ]
    )

    assert list(result) == [
        "CVE-2021-44228",
        "CVE-2024-4577",
    ]

    first_snapshot = result[
        "CVE-2021-44228"
    ]

    assert isinstance(
        first_snapshot,
        EPSSSnapshot,
    )

    assert first_snapshot.score == 0.95
    assert first_snapshot.percentile == 0.99
    assert first_snapshot.score_date == date(
        2026,
        7,
        30,
    )
    assert first_snapshot.api_version == "2026.07"

    second_snapshot = result[
        "CVE-2024-4577"
    ]

    assert second_snapshot.score == 0.80
    assert second_snapshot.percentile == 0.90


def test_fetch_by_cve_ids_sends_expected_parameters() -> None:
    response = _build_response(
        payload=_build_payload(
            _build_record()
        )
    )

    session = _build_session(
        response
    )

    connector = EPSSConnector(
        session=session,
        timeout=5,
    )

    connector.fetch_by_cve_ids(
        [
            "CVE-2021-44228",
        ],
        score_date=date(
            2026,
            7,
            30,
        ),
    )

    session.get.assert_called_once_with(
        connector.BASE_URL,
        params={
            "cve": "CVE-2021-44228",
            "limit": 1,
            "date": "2026-07-30",
        },
        timeout=5.0,
    )


def test_fetch_by_cve_ids_returns_empty_without_http_call(
) -> None:
    session = _build_session()

    connector = EPSSConnector(
        session=session,
    )

    result = connector.fetch_by_cve_ids(
        []
    )

    assert result == {}
    session.get.assert_not_called()


def test_fetch_by_cve_ids_ignores_invalid_identifiers(
) -> None:
    session = _build_session()

    connector = EPSSConnector(
        session=session,
    )

    result = connector.fetch_by_cve_ids(
        [
            "",
            "INVALID-ID",
            "CVE-2026-123",
            None,  # type: ignore[list-item]
        ]
    )

    assert result == {}
    session.get.assert_not_called()


def test_fetch_by_cve_ids_omits_missing_cves() -> None:
    response = _build_response(
        payload=_build_payload(
            _build_record(
                cve_id="CVE-2021-44228",
            )
        )
    )

    session = _build_session(
        response
    )

    connector = EPSSConnector(
        session=session,
    )

    result = connector.fetch_by_cve_ids(
        [
            "CVE-2021-44228",
            "CVE-2024-4577",
        ]
    )

    assert list(result) == [
        "CVE-2021-44228",
    ]


def test_fetch_by_cve_ids_batches_large_queries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_response = _build_response(
        payload=_build_payload(
            _build_record(
                cve_id="CVE-2026-1001",
            ),
            _build_record(
                cve_id="CVE-2026-1002",
            ),
        )
    )

    second_response = _build_response(
        payload=_build_payload(
            _build_record(
                cve_id="CVE-2026-1003",
            )
        )
    )

    session = _build_session(
        first_response,
        second_response,
    )

    connector = EPSSConnector(
        session=session,
    )

    # Deux identifiants de 13 caractères et
    # une virgule occupent exactement 27 caractères.
    monkeypatch.setattr(
        connector,
        "MAX_CVE_QUERY_LENGTH",
        27,
    )

    result = connector.fetch_by_cve_ids(
        [
            "CVE-2026-1001",
            "CVE-2026-1002",
            "CVE-2026-1003",
        ]
    )

    assert list(result) == [
        "CVE-2026-1001",
        "CVE-2026-1002",
        "CVE-2026-1003",
    ]

    assert session.get.call_count == 2

    first_params = (
        session.get.call_args_list[0]
        .kwargs["params"]
    )

    second_params = (
        session.get.call_args_list[1]
        .kwargs["params"]
    )

    assert first_params == {
        "cve": (
            "CVE-2026-1001,"
            "CVE-2026-1002"
        ),
        "limit": 2,
    }

    assert second_params == {
        "cve": "CVE-2026-1003",
        "limit": 1,
    }


def test_fetch_by_cve_ids_rejects_unexpected_cve(
) -> None:
    response = _build_response(
        payload=_build_payload(
            _build_record(
                cve_id="CVE-2024-4577",
            )
        )
    )

    session = _build_session(
        response
    )

    connector = EPSSConnector(
        session=session,
    )

    with pytest.raises(
        InvalidEPSSResponseError,
        match=(
            "unexpected CVE identifier"
        ),
    ):
        connector.fetch_by_cve_ids(
            [
                "CVE-2021-44228",
            ]
        )


def test_fetch_by_cve_ids_rejects_conflicting_duplicates(
) -> None:
    response = _build_response(
        payload=_build_payload(
            _build_record(
                score="0.80",
            ),
            _build_record(
                score="0.90",
            ),
        )
    )

    session = _build_session(
        response
    )

    connector = EPSSConnector(
        session=session,
    )

    with pytest.raises(
        InvalidEPSSResponseError,
        match=(
            "conflicting duplicate data"
        ),
    ):
        connector.fetch_by_cve_ids(
            [
                "CVE-2021-44228",
            ]
        )


@pytest.mark.parametrize(
    "invalid_data",
    [
        None,
        {},
        "invalid",
        123,
    ],
)
def test_fetch_by_cve_ids_rejects_invalid_data_field(
    invalid_data: object,
) -> None:
    payload = _build_payload()
    payload["data"] = invalid_data

    response = _build_response(
        payload=payload
    )

    session = _build_session(
        response
    )

    connector = EPSSConnector(
        session=session,
    )

    with pytest.raises(
        InvalidEPSSResponseError,
        match="'data' must be a list",
    ):
        connector.fetch_by_cve_ids(
            [
                "CVE-2021-44228",
            ]
        )


@pytest.mark.parametrize(
    (
        "field_name",
        "invalid_value",
    ),
    [
        (
            "epss",
            "invalid",
        ),
        (
            "epss",
            "1.50",
        ),
        (
            "percentile",
            "invalid",
        ),
        (
            "percentile",
            "-0.10",
        ),
        (
            "date",
            "30-07-2026",
        ),
        (
            "date",
            None,
        ),
    ],
)
def test_fetch_by_cve_ids_rejects_invalid_record_values(
    field_name: str,
    invalid_value: object,
) -> None:
    record = _build_record()

    record[field_name] = invalid_value

    response = _build_response(
        payload=_build_payload(
            record
        )
    )

    session = _build_session(
        response
    )

    connector = EPSSConnector(
        session=session,
    )

    with pytest.raises(
        InvalidEPSSResponseError,
    ):
        connector.fetch_by_cve_ids(
            [
                "CVE-2021-44228",
            ]
        )


def test_fetch_by_cve_ids_rejects_invalid_json() -> None:
    response = Mock(
        spec=requests.Response,
    )

    response.raise_for_status.return_value = None
    response.json.side_effect = ValueError(
        "invalid JSON"
    )

    session = _build_session(
        response
    )

    connector = EPSSConnector(
        session=session,
    )

    with pytest.raises(
        InvalidEPSSResponseError,
        match="invalid JSON",
    ):
        connector.fetch_by_cve_ids(
            [
                "CVE-2021-44228",
            ]
        )


def test_fetch_by_cve_ids_rejects_non_object_json(
) -> None:
    response = _build_response(
        payload=[]
    )

    session = _build_session(
        response
    )

    connector = EPSSConnector(
        session=session,
    )

    with pytest.raises(
        InvalidEPSSResponseError,
        match="must be a JSON object",
    ):
        connector.fetch_by_cve_ids(
            [
                "CVE-2021-44228",
            ]
        )


@pytest.mark.parametrize(
    "network_error",
    [
        requests.Timeout(),
        requests.ConnectionError(),
    ],
)
def test_fetch_by_cve_ids_maps_network_errors_to_unavailable(
    network_error: requests.RequestException,
) -> None:
    session = _build_session()
    session.get.side_effect = network_error

    connector = EPSSConnector(
        session=session,
    )

    with pytest.raises(
        EPSSProviderUnavailableError,
    ):
        connector.fetch_by_cve_ids(
            [
                "CVE-2021-44228",
            ]
        )


@pytest.mark.parametrize(
    "status_code",
    [
        429,
        500,
        503,
    ],
)
def test_fetch_by_cve_ids_maps_retryable_http_errors(
    status_code: int,
) -> None:
    response = Mock(
        spec=requests.Response,
    )

    response.status_code = status_code

    response.raise_for_status.side_effect = (
        requests.HTTPError(
            response=response
        )
    )

    session = _build_session(
        response
    )

    connector = EPSSConnector(
        session=session,
    )

    with pytest.raises(
        EPSSProviderUnavailableError,
        match=f"HTTP {status_code}",
    ):
        connector.fetch_by_cve_ids(
            [
                "CVE-2021-44228",
            ]
        )


def test_fetch_by_cve_ids_maps_non_retryable_http_error(
) -> None:
    response = Mock(
        spec=requests.Response,
    )

    response.status_code = 400

    response.raise_for_status.side_effect = (
        requests.HTTPError(
            response=response
        )
    )

    session = _build_session(
        response
    )

    connector = EPSSConnector(
        session=session,
    )

    with pytest.raises(
        EPSSProviderError,
        match="HTTP 400",
    ):
        connector.fetch_by_cve_ids(
            [
                "CVE-2021-44228",
            ]
        )


def test_legacy_fetch_by_cves_returns_raw_payload(
) -> None:
    payload = _build_payload(
        _build_record()
    )

    response = _build_response(
        payload=payload
    )

    session = _build_session(
        response
    )

    connector = EPSSConnector(
        session=session,
    )

    result = connector.fetch_by_cves(
        [
            "cve-2021-44228",
        ],
        date="2026-07-30",
    )

    assert result == payload

    session.get.assert_called_once_with(
        connector.BASE_URL,
        params={
            "cve": "CVE-2021-44228",
            "limit": 1,
            "date": "2026-07-30",
        },
        timeout=10.0,
    )


def test_legacy_fetch_by_cves_returns_empty_response(
) -> None:
    session = _build_session()

    connector = EPSSConnector(
        session=session,
    )

    result = connector.fetch_by_cves(
        []
    )

    assert result == {
        "status": "OK",
        "status-code": 200,
        "total": 0,
        "data": [],
    }

    session.get.assert_not_called()


def test_close_does_not_close_injected_session(
) -> None:
    session = _build_session()

    connector = EPSSConnector(
        session=session,
    )

    connector.close()

    session.close.assert_not_called()


def test_close_closes_connector_owned_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = _build_session()

    monkeypatch.setattr(
        requests,
        "Session",
        Mock(
            return_value=session,
        ),
    )

    connector = EPSSConnector()

    connector.close()

    session.close.assert_called_once_with()