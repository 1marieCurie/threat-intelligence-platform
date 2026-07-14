from __future__ import annotations

import os
from typing import Any, Dict

import pytest

from infrastructure.adapters.outbound.urlhaus_connector import (
    URLhausConnector,
)


pytestmark = pytest.mark.integration


def _get_auth_key() -> str:
    """
    Retrieve the real URLhaus Auth-Key for integration tests.

    The test is skipped rather than failed when the environment
    variable is not configured.
    """
    auth_key = os.getenv(
        "URLHAUS_AUTH_KEY",
        "",
    ).strip()

    if not auth_key:
        pytest.skip(
            "URLHAUS_AUTH_KEY is not configured."
        )

    return auth_key


def test_integration_fetch_recent_urls() -> None:
    """
    Perform a real request against the URLhaus recent URLs API.
    """
    connector = URLhausConnector(
        auth_key=_get_auth_key(),
        timeout=30,
    )

    result = connector.fetch_recent_urls(limit=5)

    print(
        "\n[URLHAUS INTEGRATION] Recent URLs"
    )
    print(
        f"Query status : {result.get('query_status')}"
    )

    assert isinstance(result, dict)
    assert result.get("query_status") in {
        "ok",
        "no_results",
    }

    if result["query_status"] == "no_results":
        print("No recent URLhaus result available.")
        return

    urls = result.get("urls")

    assert isinstance(urls, list)
    assert len(urls) <= 5

    print(f"URLs received : {len(urls)}")

    if not urls:
        return

    first = urls[0]

    assert isinstance(first, dict)

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

    missing_fields = required_fields - first.keys()

    assert not missing_fields, (
        "The first URLhaus record is missing fields: "
        f"{sorted(missing_fields)}"
    )

    assert isinstance(first["id"], (int, str))
    assert isinstance(first["urlhaus_reference"], str)
    assert isinstance(first["url"], str)
    assert isinstance(first["url_status"], str)
    assert isinstance(first["host"], str)
    assert isinstance(first["date_added"], str)
    assert isinstance(first["threat"], str)
    assert isinstance(first["blacklists"], dict)
    assert isinstance(first["reporter"], str)
    assert isinstance(first["tags"], list)

    print(f"First ID      : {first['id']}")
    print(f"URL status    : {first['url_status']}")
    print(f"Host          : {first['host']}")
    print(f"Threat type   : {first['threat']}")
    print(f"Date added    : {first['date_added']}")
    print(f"Tags          : {first['tags']}")
    print(
        f"Reference     : "
        f"{first['urlhaus_reference']}"
    )

    # Do not print or open the malicious URL itself.

def test_integration_fetch_url_information_by_id() -> None:
    """
    Fetch recent URLs, then query the first entry using its
    URLhaus identifier.
    """
    connector = URLhausConnector(
        auth_key=_get_auth_key(),
        timeout=30,
    )

    recent_result = connector.fetch_recent_urls(
        limit=1
    )

    if recent_result.get("query_status") != "ok":
        pytest.skip(
            "No recent URLhaus URL available."
        )

    recent_urls = recent_result.get("urls", [])

    if not recent_urls:
        pytest.skip(
            "URLhaus returned an empty URL list."
        )

    recent_entry = recent_urls[0]
    urlhaus_id = recent_entry["id"]

    details = connector.fetch_url_information_by_id(
        urlhaus_id
    )

    print(
        "\n[URLHAUS INTEGRATION] URL details"
    )
    print(f"URLhaus ID    : {urlhaus_id}")
    print(
        f"Query status  : "
        f"{details.get('query_status')}"
    )

    assert isinstance(details, dict)
    assert details.get("query_status") == "ok"

    assert str(details.get("id")) == str(
        urlhaus_id
    )

    assert isinstance(details.get("url"), str)
    assert isinstance(
        details.get("urlhaus_reference"),
        str,
    )
    assert isinstance(
        details.get("url_status"),
        str,
    )
    assert isinstance(details.get("host"), str)
    assert isinstance(details.get("threat"), str)

    payloads = details.get("payloads", [])

    assert payloads is None or isinstance(
        payloads,
        list,
    )

    print(
        f"URL status    : "
        f"{details.get('url_status')}"
    )
    print(
        f"Host          : {details.get('host')}"
    )
    print(
        f"Threat type   : "
        f"{details.get('threat')}"
    )
    print(
        f"Last online   : "
        f"{details.get('last_online')}"
    )
    print(
        f"Payload count : "
        f"{len(payloads or [])}"
    )

    if payloads:
        first_payload = payloads[0]

        assert isinstance(first_payload, dict)

        print(
            f"Payload type  : "
            f"{first_payload.get('file_type')}"
        )
        print(
            f"Signature     : "
            f"{first_payload.get('signature')}"
        )
        print(
            f"SHA-256 found : "
            f"{bool(first_payload.get('response_sha256'))}"
        )

def test_integration_fetch_host_information() -> None:
    """
    Retrieve one recent URL, then query URLhaus using its host.
    """
    connector = URLhausConnector(
        auth_key=_get_auth_key(),
        timeout=30,
    )

    recent_result = connector.fetch_recent_urls(
        limit=1
    )

    if recent_result.get("query_status") != "ok":
        pytest.skip(
            "No recent URLhaus URL available."
        )

    recent_urls = recent_result.get("urls", [])

    if not recent_urls:
        pytest.skip(
            "URLhaus returned an empty URL list."
        )

    host = recent_urls[0].get("host")

    if not isinstance(host, str) or not host.strip():
        pytest.skip(
            "The recent URLhaus entry has no host."
        )

    result = connector.fetch_host_information(host)

    print(
        "\n[URLHAUS INTEGRATION] Host lookup"
    )
    print(f"Host          : {host}")
    print(
        f"Query status  : "
        f"{result.get('query_status')}"
    )

    assert isinstance(result, dict)
    assert result.get("query_status") in {
        "ok",
        "no_results",
    }

    if result["query_status"] == "no_results":
        return

    assert result.get("host") == host

    urls = result.get("urls", [])

    assert isinstance(urls, list)

    print(f"Related URLs  : {len(urls)}")