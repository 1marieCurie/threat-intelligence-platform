from __future__ import annotations

import os

import pytest

from application.services.urlhaus_threat_source import (
    URLhausThreatSource,
)
from domain.collection_result import CollectionResult
from domain.indicator import Indicator
from domain.threat import Threat
from infrastructure.adapters.outbound.urlhaus_connector import (
    URLhausConnector,
)


pytestmark = pytest.mark.integration


def _get_auth_key() -> str:
    auth_key = os.getenv(
        "URLHAUS_AUTH_KEY",
        "",
    ).strip()

    if not auth_key:
        pytest.skip(
            "URLHAUS_AUTH_KEY is not configured."
        )

    return auth_key


def test_integration_collect_recent_urlhaus_threats() -> None:
    connector = URLhausConnector(
        auth_key=_get_auth_key(),
        timeout=30,
    )

    source = URLhausThreatSource(
        connector=connector,
        limit=5,
        enrich_with_details=False,
    )

    result = source.collect()

    print(
        "\n[URLHAUS SERVICE INTEGRATION] "
        "Recent threat collection"
    )

    print(
        f"Query status       : "
        f"{result.metadata.get('query_status')}"
    )

    print(
        f"Received records   : "
        f"{result.metadata.get('received_records')}"
    )

    print(
        f"Parsed threats     : "
        f"{result.metadata.get('parsed_threats')}"
    )

    print(
        f"Skipped records    : "
        f"{result.metadata.get('skipped_records')}"
    )

    assert isinstance(result, CollectionResult)

    assert result.metadata["source"] == "URLHAUS"

    assert result.metadata["query_status"] in {
        "ok",
        "no_results",
    }

    if result.metadata["query_status"] == "no_results":
        assert result.threats == []
        return

    assert isinstance(result.threats, list)
    assert len(result.threats) <= 5

    if not result.threats:
        pytest.skip(
            "URLhaus returned no parseable recent threats."
        )

    first = result.threats[0]

    assert isinstance(first, Threat)

    assert first.id.startswith("URLHAUS-")

    assert first.source == "URLHAUS"

    assert first.threat_type == (
        "malware_distribution"
    )

    assert "URLHAUS" in first.external_ids

    assert len(first.external_ids["URLHAUS"]) == 1

    assert isinstance(first.description, str)
    assert first.description

    assert isinstance(first.indicators, list)
    assert first.indicators

    url_indicators = [
        indicator
        for indicator in first.indicators
        if indicator.type == "url"
    ]

    assert len(url_indicators) == 1

    assert isinstance(
        url_indicators[0],
        Indicator,
    )

    assert url_indicators[0].value

    host_indicators = [
        indicator
        for indicator in first.indicators
        if indicator.type in {
            "domain",
            "ipv4",
            "ipv6",
        }
    ]

    assert len(host_indicators) <= 1

    assert isinstance(first.raw, dict)
    assert first.raw

    print(f"First threat ID    : {first.id}")
    print(f"Title              : {first.title}")
    print(f"Threat type        : {first.threat_type}")
    print(f"Advisory type      : {first.advisory_type}")
    print(f"Labels             : {first.labels}")

    print(
        "Indicator types    : "
        f"{[i.type for i in first.indicators]}"
    )

    print(
        f"Source dates       : "
        f"{first.source_dates}"
    )

    print(
        f"Reference count    : "
        f"{len(first.references)}"
    )

    # Do not print the malicious URL value.
def test_integration_collect_urlhaus_with_details() -> None:
    connector = URLhausConnector(
        auth_key=_get_auth_key(),
        timeout=30,
    )

    source = URLhausThreatSource(
        connector=connector,
        limit=2,
        enrich_with_details=True,
        max_detail_requests=2,
    )

    result = source.collect()

    print(
        "\n[URLHAUS SERVICE INTEGRATION] "
        "Detailed threat enrichment"
    )

    print(
        f"Query status       : "
        f"{result.metadata.get('query_status')}"
    )

    print(
        f"Parsed threats     : "
        f"{result.metadata.get('parsed_threats')}"
    )

    assert isinstance(result, CollectionResult)

    assert result.metadata[
        "details_enrichment_enabled"
    ] is True

    assert result.metadata[
        "max_detail_requests"
    ] == 2

    if result.metadata["query_status"] != "ok":
        pytest.skip(
            "No recent URLhaus results available."
        )

    if not result.threats:
        pytest.skip(
            "No URLhaus threat could be parsed."
        )

    first = result.threats[0]

    assert isinstance(first, Threat)

    indicator_types = {
        indicator.type
        for indicator in first.indicators
    }

    assert "url" in indicator_types

    assert indicator_types.intersection(
        {
            "domain",
            "ipv4",
            "ipv6",
        }
    )

    hash_indicators = [
        indicator
        for indicator in first.indicators
        if indicator.type in {
            "md5",
            "sha256",
        }
    ]

    print(f"First threat ID    : {first.id}")
    print(f"Labels             : {first.labels}")

    print(
        f"Indicator types    : "
        f"{sorted(indicator_types)}"
    )

    print(
        f"Hash indicators    : "
        f"{len(hash_indicators)}"
    )

    for indicator in hash_indicators:
        assert isinstance(indicator.value, str)
        assert indicator.value

        assert indicator.metadata.get(
            "source"
        ) == "URLHAUS"

        assert indicator.metadata.get(
            "urlhaus_id"
        )

        if indicator.type == "md5":
            assert len(indicator.value) == 32

        if indicator.type == "sha256":
            assert len(indicator.value) == 64

        print(
            f"{indicator.type.upper()} found       : True"
        )

    # A recent URL does not always have a downloadable payload.
    # Therefore, the absence of hash indicators is not a failure.
def test_integration_host_indicator_type_is_valid() -> None:
    connector = URLhausConnector(
        auth_key=_get_auth_key(),
        timeout=30,
    )

    source = URLhausThreatSource(
        connector=connector,
        limit=5,
    )

    result = source.collect()

    if result.metadata.get("query_status") != "ok":
        pytest.skip(
            "No recent URLhaus results available."
        )

    if not result.threats:
        pytest.skip(
            "No parseable URLhaus threats available."
        )

    print(
        "\n[URLHAUS SERVICE INTEGRATION] "
        "Host indicator validation"
    )

    checked_hosts = 0

    for threat in result.threats:
        host_indicators = [
            indicator
            for indicator in threat.indicators
            if indicator.type in {
                "domain",
                "ipv4",
                "ipv6",
            }
        ]

        assert len(host_indicators) <= 1

        if not host_indicators:
            continue

        host_indicator = host_indicators[0]

        assert host_indicator.value
        assert host_indicator.type in {
            "domain",
            "ipv4",
            "ipv6",
        }

        checked_hosts += 1

        print(
            f"{threat.id}: "
            f"{host_indicator.type}"
        )

    assert checked_hosts >= 1
