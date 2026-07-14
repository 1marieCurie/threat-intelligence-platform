from __future__ import annotations

import os

import pytest

from application.services.urlhaus_threat_source import (
    URLhausThreatSource,
)
from domain.collection_result import CollectionResult
from domain.threat import Threat
from infrastructure.adapters.inbound.urlhaus_ingestion_job import (
    URLhausIngestionJob,
)
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


def test_integration_run_urlhaus_ingestion_job() -> None:
    connector = URLhausConnector(
        auth_key=_get_auth_key(),
        timeout=30,
    )

    source = URLhausThreatSource(
        connector=connector,
        limit=5,
        enrich_with_details=False,
    )

    job = URLhausIngestionJob(source)

    result = job.run()

    print(
        "\n[URLHAUS INGESTION JOB INTEGRATION]"
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

    assert len(result.threats) <= 5

    if not result.threats:
        pytest.skip(
            "No parseable URLhaus threats were returned."
        )

    first = result.threats[0]

    assert isinstance(first, Threat)
    assert first.id.startswith("URLHAUS-")
    assert first.source == "URLHAUS"
    assert first.threat_type == (
        "malware_distribution"
    )

    assert first.indicators

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

    print(f"First threat ID    : {first.id}")
    print(f"Title              : {first.title}")
    print(f"Threat type        : {first.threat_type}")

    print(
        "Indicator types    : "
        f"{sorted(indicator_types)}"
    )

    print(f"Labels             : {first.labels}")

    # Do not print the malicious URL values.
def test_integration_run_urlhaus_job_with_details() -> None:
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

    job = URLhausIngestionJob(source)

    result = job.run()

    print(
        "\n[URLHAUS INGESTION JOB INTEGRATION] "
        "Detailed enrichment"
    )

    assert isinstance(result, CollectionResult)

    assert result.metadata[
        "details_enrichment_enabled"
    ] is True

    assert result.metadata[
        "max_detail_requests"
    ] == 2

    if result.metadata.get("query_status") != "ok":
        pytest.skip(
            "No recent URLhaus records available."
        )

    if not result.threats:
        pytest.skip(
            "No parseable URLhaus threats available."
        )

    first = result.threats[0]

    indicator_types = {
        indicator.type
        for indicator in first.indicators
    }

    assert "url" in indicator_types

    hash_indicators = [
        indicator
        for indicator in first.indicators
        if indicator.type in {
            "md5",
            "sha256",
        }
    ]

    print(f"First threat ID    : {first.id}")
    print(
        f"Indicator types    : "
        f"{sorted(indicator_types)}"
    )
    print(
        f"Hash indicators    : "
        f"{len(hash_indicators)}"
    )

    for indicator in hash_indicators:
        assert indicator.metadata.get(
            "source"
        ) == "URLHAUS"

        if indicator.type == "md5":
            assert len(indicator.value) == 32

        if indicator.type == "sha256":
            assert len(indicator.value) == 64