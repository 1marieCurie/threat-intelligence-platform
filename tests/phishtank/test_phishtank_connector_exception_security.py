from __future__ import annotations

import traceback
from unittest.mock import Mock

import pytest
import requests

from infrastructure.adapters.outbound.phishtank_connector import (
    PhishTankConnector,
    PhishTankConnectorError,
)


SECRET_APP_KEY = "secret-phishtank-app-key"

AUTHENTICATED_URL = (
    "https://data.phishtank.com/data/"
    f"{SECRET_APP_KEY}/"
    "online-valid.json.bz2"
)


def _render_exception(
    error: BaseException,
) -> str:
    return "".join(
        traceback.format_exception(
            type(error),
            error,
            error.__traceback__,
        )
    )


def _assert_exception_is_sanitized(
    error: PhishTankConnectorError,
) -> None:
    rendered_exception = _render_exception(
        error
    )

    assert SECRET_APP_KEY not in str(
        error
    )

    assert SECRET_APP_KEY not in (
        rendered_exception
    )

    assert AUTHENTICATED_URL not in (
        rendered_exception
    )

    assert error.__cause__ is None
    assert error.__context__ is None


def test_metadata_error_does_not_retain_authenticated_url(
    tmp_path,
) -> None:
    session = Mock()

    session.head.side_effect = (
        requests.RequestException(
            "HEAD request failed for "
            f"{AUTHENTICATED_URL}"
        )
    )

    connector = PhishTankConnector(
        storage_directory=tmp_path,
        app_key=SECRET_APP_KEY,
        session=session,
    )

    with pytest.raises(
        PhishTankConnectorError,
        match=(
            "Unable to retrieve PhishTank "
            "remote metadata"
        ),
    ) as exc_info:
        connector.get_remote_metadata()

    _assert_exception_is_sanitized(
        exc_info.value
    )


def test_download_error_does_not_retain_authenticated_url(
    tmp_path,
) -> None:
    session = Mock()

    head_response = Mock()
    head_response.headers = {
        "ETag": '"test-etag"',
    }

    head_response.raise_for_status.return_value = (
        None
    )

    session.head.return_value = (
        head_response
    )

    session.get.side_effect = (
        requests.RequestException(
            "GET request failed for "
            f"{AUTHENTICATED_URL}"
        )
    )

    connector = PhishTankConnector(
        storage_directory=tmp_path,
        app_key=SECRET_APP_KEY,
        session=session,
    )

    with pytest.raises(
        PhishTankConnectorError,
        match=(
            "Unable to download the "
            "PhishTank snapshot"
        ),
    ) as exc_info:
        connector.fetch_raw(
            force_download=True,
            limit=1,
        )

    _assert_exception_is_sanitized(
        exc_info.value
    )

    assert not connector.dump_path.exists()

    temporary_path = (
        connector.dump_path.with_suffix(
            connector.dump_path.suffix
            + ".tmp"
        )
    )

    assert not temporary_path.exists()