from pathlib import Path

import pytest

from application.services.phishtank_threat_source import (
    PhishTankThreatSource,
)
from domain.collection_result import CollectionResult
from domain.indicator import Indicator
from domain.threat import Threat
from infrastructure.adapters.outbound.phishtank_connector import (
    PhishTankConnector,
)


@pytest.mark.integration
def test_integration_collect_real_phishtank_threats(
    tmp_path: Path,
) -> None:
    """
    Download a real PhishTank snapshot and normalize a small
    number of records into Threat objects.

    The full snapshot is downloaded, but only three records are
    returned and normalized.
    """

    connector = PhishTankConnector(
        storage_directory=(
            tmp_path / "phishtank"
        ),
        user_agent=(
            "threat-intelligence-engine/"
            "phishtank-source-integration-test"
        ),
        timeout=60.0,
    )

    source = PhishTankThreatSource(
        connector=connector,
        limit=3,
        force_download=True,
    )

    result = source.collect()

    assert isinstance(
        result,
        CollectionResult,
    )

    assert len(result.threats) == 3

    for threat in result.threats:
        assert isinstance(threat, Threat)

        assert threat.id.startswith(
            "PHISHTANK-"
        )

        assert threat.source == "PHISHTANK"
        assert threat.threat_type == "phishing"

        assert threat.external_ids.get(
            "PHISHTANK"
        )

        assert isinstance(
            threat.raw,
            dict,
        )

        assert "phish_id" in threat.raw
        assert "url" in threat.raw

        assert len(threat.indicators) >= 1

        url_indicators = [
            indicator
            for indicator in threat.indicators
            if indicator.type == "url"
        ]

        assert len(url_indicators) == 1

        url_indicator = url_indicators[0]

        assert isinstance(
            url_indicator,
            Indicator,
        )

        assert url_indicator.value
        assert (
            url_indicator.metadata["source"]
            == "PHISHTANK"
        )

    assert result.metadata["source"] == "PHISHTANK"
    assert result.metadata["raw_record_count"] == 3
    assert result.metadata["threat_count"] == 3
    assert result.metadata["skipped_record_count"] == 0

    assert result.metadata["verified_only"] is True
    assert result.metadata["online_only"] is True

    assert connector.dump_path.exists()
    assert connector.dump_path.stat().st_size > 0
    
@pytest.mark.integration
def test_integration_real_indicator_status_metadata(
    tmp_path: Path,
) -> None:
    """
    Verify that status metadata attached to real indicators is
    derived from the real PhishTank record.
    """

    connector = PhishTankConnector(
        storage_directory=(
            tmp_path / "phishtank"
        ),
        user_agent=(
            "threat-intelligence-engine/"
            "phishtank-metadata-integration-test"
        ),
        timeout=60.0,
    )

    source = PhishTankThreatSource(
        connector=connector,
        limit=1,
        force_download=True,
    )

    result = source.collect()

    assert len(result.threats) == 1

    threat = result.threats[0]

    url_indicator = next(
        indicator
        for indicator in threat.indicators
        if indicator.type == "url"
    )

    raw_verified = threat.raw.get("verified")
    raw_online = threat.raw.get("online")

    if (
        isinstance(raw_verified, str)
        and raw_verified.strip().lower() == "yes"
    ):
        assert (
            url_indicator.metadata["verified"]
            is True
        )

        assert url_indicator.confidence == 1.0

    if (
        isinstance(raw_online, str)
        and raw_online.strip().lower() == "yes"
    ):
        assert (
            url_indicator.metadata["online"]
            is True
        )