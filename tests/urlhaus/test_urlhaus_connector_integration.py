from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any

import pytest

from infrastructure.adapters.outbound.urlhaus_connector import (
    URLhausConnector,
    URLhausHTTPError,
)


pytestmark = [
    pytest.mark.integration,
    pytest.mark.external,
]


def _get_auth_key() -> str:
    """
    Récupère la clé URLhaus utilisée exclusivement
    par les tests d'intégration externes.

    La valeur ne doit jamais être affichée, journalisée
    ou incluse dans un message de skip.
    """

    auth_key = os.environ.get(
        "URLHAUS_AUTH_KEY",
        "",
    ).strip()

    if not auth_key:
        pytest.skip(
            "URLHAUS_AUTH_KEY is not configured."
        )

    return auth_key


def _call_urlhaus_or_skip(
    operation: Callable[
        [],
        dict[str, Any],
    ],
) -> dict[str, Any]:
    """
    Exécute une opération HTTP réelle URLhaus.

    Une erreur HTTP ou réseau entraîne un skip, car elle
    dépend de l'environnement externe.

    Les erreurs d'authentification, de réponse JSON ou
    de contrat fonctionnel restent des échecs réels.
    """

    try:
        return operation()

    except URLhausHTTPError:
        pytest.skip(
            "URLhaus live API is currently "
            "unavailable or unreachable."
        )


def _build_connector() -> URLhausConnector:
    """
    Construit le connecteur live sans exposer
    la clé d'authentification.
    """

    return URLhausConnector(
        auth_key=_get_auth_key(),
        timeout=30,
    )


def _fetch_recent_urls_or_skip(
    connector: URLhausConnector,
    *,
    limit: int,
) -> dict[str, Any]:
    return _call_urlhaus_or_skip(
        lambda: connector.fetch_recent_urls(
            limit=limit
        )
    )


def test_integration_fetch_recent_urls(
) -> None:
    """
    Effectue une requête réelle sur l'API
    URLhaus des URLs récentes.
    """

    connector = _build_connector()

    result = _fetch_recent_urls_or_skip(
        connector,
        limit=5,
    )

    assert isinstance(
        result,
        dict,
    )

    assert result.get(
        "query_status"
    ) in {
        "ok",
        "no_results",
    }

    if (
        result["query_status"]
        == "no_results"
    ):
        return

    urls = result.get(
        "urls"
    )

    assert isinstance(
        urls,
        list,
    )

    assert len(urls) <= 5

    if not urls:
        return

    first = urls[0]

    assert isinstance(
        first,
        dict,
    )

    required_fields = {
        "id",
        "urlhaus_reference",
        "url",
        "url_status",
        "host",
        "date_added",
        "threat",
        "blacklists",
        "reporter",
        "larted",
        "tags",
    }

    missing_fields = (
        required_fields
        - first.keys()
    )

    assert not missing_fields, (
        "The first URLhaus record is "
        "missing fields: "
        f"{sorted(missing_fields)}"
    )

    assert isinstance(
        first["id"],
        (int, str),
    )

    assert isinstance(
        first["urlhaus_reference"],
        str,
    )

    assert isinstance(
        first["url"],
        str,
    )

    assert isinstance(
        first["url_status"],
        str,
    )

    assert isinstance(
        first["host"],
        str,
    )

    assert isinstance(
        first["date_added"],
        str,
    )

    assert isinstance(
        first["threat"],
        str,
    )

    assert isinstance(
        first["blacklists"],
        dict,
    )

    assert isinstance(
        first["reporter"],
        str,
    )

    assert isinstance(
        first["larted"],
        (bool, str),
    )

    tags = first["tags"]

    assert (
        tags is None
        or isinstance(
            tags,
            list,
        )
    )

    if isinstance(
        tags,
        list,
    ):
        assert all(
            isinstance(
                tag,
                str,
            )
            for tag in tags
        )

    # Ne jamais afficher ni ouvrir l'URL malveillante.
    assert first["url"].strip()


def test_integration_fetch_url_information_by_id(
) -> None:
    """
    Récupère une URL récente puis interroge
    son identifiant URLhaus.
    """

    connector = _build_connector()

    recent_result = (
        _fetch_recent_urls_or_skip(
            connector,
            limit=1,
        )
    )

    if (
        recent_result.get(
            "query_status"
        )
        != "ok"
    ):
        pytest.skip(
            "No recent URLhaus URL "
            "is currently available."
        )

    recent_urls = recent_result.get(
        "urls",
        [],
    )

    if not isinstance(
        recent_urls,
        list,
    ):
        pytest.fail(
            "URLhaus recent URLs field "
            "must be a list."
        )

    if not recent_urls:
        pytest.skip(
            "URLhaus returned an empty "
            "recent URL list."
        )

    recent_entry = recent_urls[0]

    assert isinstance(
        recent_entry,
        dict,
    )

    urlhaus_id = recent_entry.get(
        "id"
    )

    assert isinstance(
        urlhaus_id,
        (int, str),
    )

    details = _call_urlhaus_or_skip(
        lambda: (
            connector
            .fetch_url_information_by_id(
                urlhaus_id
            )
        )
    )

    assert isinstance(
        details,
        dict,
    )

    assert (
        details.get("query_status")
        == "ok"
    )

    assert str(
        details.get("id")
    ) == str(
        urlhaus_id
    )

    assert isinstance(
        details.get("url"),
        str,
    )

    assert isinstance(
        details.get(
            "urlhaus_reference"
        ),
        str,
    )

    assert isinstance(
        details.get("url_status"),
        str,
    )

    assert isinstance(
        details.get("host"),
        str,
    )

    assert isinstance(
        details.get("threat"),
        str,
    )

    payloads = details.get(
        "payloads",
        [],
    )

    assert (
        payloads is None
        or isinstance(
            payloads,
            list,
        )
    )

    if payloads:
        first_payload = payloads[0]

        assert isinstance(
            first_payload,
            dict,
        )

        response_sha256 = (
            first_payload.get(
                "response_sha256"
            )
        )

        if response_sha256 is not None:
            assert isinstance(
                response_sha256,
                str,
            )

            assert len(
                response_sha256
            ) == 64


def test_integration_fetch_host_information(
) -> None:
    """
    Récupère une URL récente puis interroge
    URLhaus à partir de son hôte.
    """

    connector = _build_connector()

    recent_result = (
        _fetch_recent_urls_or_skip(
            connector,
            limit=1,
        )
    )

    if (
        recent_result.get(
            "query_status"
        )
        != "ok"
    ):
        pytest.skip(
            "No recent URLhaus URL "
            "is currently available."
        )

    recent_urls = recent_result.get(
        "urls",
        [],
    )

    if not isinstance(
        recent_urls,
        list,
    ):
        pytest.fail(
            "URLhaus recent URLs field "
            "must be a list."
        )

    if not recent_urls:
        pytest.skip(
            "URLhaus returned an empty "
            "recent URL list."
        )

    recent_entry = recent_urls[0]

    assert isinstance(
        recent_entry,
        dict,
    )

    host = recent_entry.get(
        "host"
    )

    if (
        not isinstance(host, str)
        or not host.strip()
    ):
        pytest.skip(
            "The recent URLhaus entry "
            "has no usable host."
        )

    normalized_host = host.strip()

    result = _call_urlhaus_or_skip(
        lambda: (
            connector
            .fetch_host_information(
                normalized_host
            )
        )
    )

    assert isinstance(
        result,
        dict,
    )

    assert result.get(
        "query_status"
    ) in {
        "ok",
        "no_results",
    }

    if (
        result["query_status"]
        == "no_results"
    ):
        return

    assert (
        result.get("host")
        == normalized_host
    )

    urls = result.get(
        "urls",
        [],
    )

    assert isinstance(
        urls,
        list,
    )