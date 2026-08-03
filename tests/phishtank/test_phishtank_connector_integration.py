from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from infrastructure.adapters.outbound.phishtank_connector import (
    PhishTankConnector,
    PhishTankConnectorError,
)


pytestmark = [
    pytest.mark.integration,
    pytest.mark.external,
    pytest.mark.external_unstable,
]


_METADATA_NETWORK_ERROR = (
    "Unable to retrieve PhishTank "
    "remote metadata."
)

_DOWNLOAD_NETWORK_ERROR = (
    "Unable to download the "
    "PhishTank snapshot."
)


def _get_remote_metadata_or_skip(
    connector: PhishTankConnector,
) -> dict[str, Any]:
    """
    Exécute une requête HEAD réelle.

    Seule l'indisponibilité connue de l'endpoint
    externe entraîne un skip.
    """

    try:
        return connector.get_remote_metadata()

    except PhishTankConnectorError as error:
        if str(error) != _METADATA_NETWORK_ERROR:
            raise

        pytest.skip(
            "PhishTank metadata endpoint "
            "is currently unavailable."
        )


def _download_snapshot_or_skip(
    connector: PhishTankConnector,
) -> list[dict[str, Any]]:
    """
    Télécharge et lit trois entrées du snapshot réel.

    Les erreurs locales de validation, de lecture ou de
    persistance restent des échecs de test.
    """

    try:
        return connector.fetch_raw(
            force_download=True,
            limit=3,
        )

    except PhishTankConnectorError as error:
        if str(error) != _DOWNLOAD_NETWORK_ERROR:
            raise

        pytest.skip(
            "PhishTank snapshot endpoint "
            "is currently unavailable or rate-limited."
        )


def _assert_public_urls_are_safe(
    state: dict[str, Any],
) -> None:
    """
    Vérifie que les URLs persistées sont uniquement
    les URLs publiques PhishTank.

    Une URL authentifiée ou contenant une clé ne doit
    jamais être persistée.
    """

    expected_public_url = (
        PhishTankConnector.PUBLIC_DOWNLOAD_URL
    )

    assert (
        state["source_url"]
        == expected_public_url
    )

    assert (
        state["download_url"]
        == expected_public_url
    )

    for url_field in (
        "source_url",
        "download_url",
    ):
        stored_url = state[url_field]

        assert isinstance(
            stored_url,
            str,
        )

        normalized_url = stored_url.lower()

        assert "app_key=" not in normalized_url
        assert "api_key=" not in normalized_url
        assert "token=" not in normalized_url
        assert "authorization=" not in normalized_url
        assert "password=" not in normalized_url
        assert "secret=" not in normalized_url


def test_integration_get_real_phishtank_metadata(
    tmp_path: Path,
) -> None:
    """
    Effectue uniquement une requête HEAD réelle.

    Aucun snapshot complet n'est téléchargé.
    """

    connector = PhishTankConnector(
        storage_directory=(
            tmp_path / "phishtank"
        ),
        user_agent=(
            "threat-intelligence-engine/"
            "integration-test"
        ),
        timeout=30.0,
    )

    metadata = _get_remote_metadata_or_skip(
        connector
    )

    assert isinstance(
        metadata,
        dict,
    )

    assert set(metadata) == {
        "etag",
        "last_modified",
        "content_length",
    }

    assert any(
        metadata[field_name] is not None
        for field_name in (
            "etag",
            "last_modified",
            "content_length",
        )
    )

    content_length = metadata[
        "content_length"
    ]

    if content_length is not None:
        assert isinstance(
            content_length,
            int,
        )

        assert content_length > 0


def test_integration_download_and_read_real_snapshot(
    tmp_path: Path,
) -> None:
    """
    Télécharge le snapshot public réel puis lit
    trois enregistrements.

    Ce test dépend d'un endpoint externe susceptible
    d'être limité ou temporairement indisponible.
    """

    connector = PhishTankConnector(
        storage_directory=(
            tmp_path / "phishtank"
        ),
        user_agent=(
            "threat-intelligence-engine/"
            "integration-test"
        ),
        timeout=60.0,
    )

    records = _download_snapshot_or_skip(
        connector
    )

    assert len(records) == 3

    for record in records:
        assert isinstance(
            record,
            dict,
        )

        assert "phish_id" in record
        assert "url" in record
        assert "verified" in record
        assert "online" in record

    assert connector.dump_path.exists()

    assert (
        connector.dump_path.stat().st_size
        > 0
    )

    state = connector.get_local_state()

    assert isinstance(
        state,
        dict,
    )

    assert state["source"] == "PHISHTANK"
    assert state["downloaded"] is True

    assert (
        state["used_local_snapshot"]
        is False
    )

    assert state["dump_path"] == str(
        connector.dump_path
    )

    # Les noms de secrets ne doivent jamais
    # être présents dans l'état persistant.
    sensitive_keys = {
        "app_key",
        "api_key",
        "token",
        "authorization",
        "password",
        "secret",
    }

    assert (
        sensitive_keys.isdisjoint(
            state
        )
    )

    _assert_public_urls_are_safe(
        state
    )