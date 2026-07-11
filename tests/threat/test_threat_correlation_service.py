from domain.threat import Threat
from domain.collection_result import CollectionResult

from application.services.threat_correlation_service import (
    ThreatCorrelationService,
    ThreatCorrelationResult,
    CorrelatedThreat
)

from application.services.nvd_threat_source import NVDThreatSource
from application.services.cisa_threat_source import CISAThreatSource
from application.services.mitre_threat_source import MITREThreatSource

from infrastructure.persistence.mitre_sync_state import MITRESyncState

import pytest

def _build_fake_collection_results():
    """
    Builds fake CollectionResult objects to test the correlation logic
    without relying on external APIs.
    """

    nvd_result = CollectionResult(
        threats=[
            Threat(
                id="CVE-2026-0001",
                description="NVD description",
                severity="HIGH",
                cvss_score=8.8
            ),
            Threat(
                id="CVE-2026-0002",
                description="Only in NVD"
            )
        ],
        metadata={
            "source": "NVD"
        }
    )

    cisa_result = CollectionResult(
        threats=[
            Threat(
                id="CVE-2026-0001",
                title="CISA known exploited vulnerability",
                known_exploited_date="2026-07-10"
            ),
            Threat(
                id="CVE-2026-0003",
                description="Only in CISA"
            )
        ],
        metadata={
            "source": "CISA"
        }
    )

    mitre_result = CollectionResult(
        threats=[
            Threat(
                id="CVE-2026-0001",
                title="MITRE fresh CVE record"
            ),
            Threat(
                id="CVE-2026-0004",
                description="Only in MITRE"
            )
        ],
        metadata={
            "source": "MITRE"
        }
    )

    return [
        nvd_result,
        cisa_result,
        mitre_result
    ]


def test_correlates_threats_by_cve_id():

    service = ThreatCorrelationService()

    results = _build_fake_collection_results()

    correlation_result = service.correlate_results(
        results
    )

    print("\n[CORRELATION SERVICE] Correlation by CVE ID")
    print(f"Unique CVE IDs: {correlation_result.metadata['unique_threats']}")
    print(f"Total input threats: {correlation_result.metadata['total_input_threats']}")

    assert isinstance(
        correlation_result,
        ThreatCorrelationResult
    )

    assert "CVE-2026-0001" in correlation_result.groups
    assert "CVE-2026-0002" in correlation_result.groups
    assert "CVE-2026-0003" in correlation_result.groups
    assert "CVE-2026-0004" in correlation_result.groups

    assert correlation_result.metadata["unique_threats"] == 4
    assert correlation_result.metadata["total_input_threats"] == 6


def test_detects_multi_source_threats():

    service = ThreatCorrelationService()

    results = _build_fake_collection_results()

    correlation_result = service.correlate_results(
        results
    )

    group = correlation_result.groups[
        "CVE-2026-0001"
    ]

    print("\n[CORRELATION SERVICE] Multi-source threat detected")
    print(f"CVE ID: {group.id}")
    print(f"Sources: {group.sources}")
    print(f"Source count: {group.source_count}")
    print(f"Threat records in group: {len(group.threats)}")

    assert isinstance(
        group,
        CorrelatedThreat
    )

    assert group.is_multi_source is True
    assert group.source_count == 3

    assert set(group.sources) == {
        "NVD",
        "CISA",
        "MITRE"
    }

    assert len(group.threats) == 3


def test_preserves_original_source_specific_threats():

    service = ThreatCorrelationService()

    results = _build_fake_collection_results()

    correlation_result = service.correlate_results(
        results
    )

    group = correlation_result.groups[
        "CVE-2026-0001"
    ]

    print("\n[CORRELATION SERVICE] Source-specific records preserved")
    print(f"NVD records: {len(group.threats_by_source['NVD'])}")
    print(f"CISA records: {len(group.threats_by_source['CISA'])}")
    print(f"MITRE records: {len(group.threats_by_source['MITRE'])}")

    assert "NVD" in group.threats_by_source
    assert "CISA" in group.threats_by_source
    assert "MITRE" in group.threats_by_source

    assert group.threats_by_source["NVD"][0].severity == "HIGH"
    assert group.threats_by_source["CISA"][0].known_exploited_date == "2026-07-10"
    assert group.threats_by_source["MITRE"][0].title == "MITRE fresh CVE record"


def test_correlation_metadata():

    service = ThreatCorrelationService()

    results = _build_fake_collection_results()

    correlation_result = service.correlate_results(
        results
    )

    print("\n[CORRELATION SERVICE] Metadata")
    for key, value in correlation_result.metadata.items():
        print(f"{key}: {value}")

    assert correlation_result.metadata["total_sources"] == 3
    assert correlation_result.metadata["total_input_threats"] == 6
    assert correlation_result.metadata["unique_threats"] == 4
    assert correlation_result.metadata["multi_source_threats"] == 1

    assert correlation_result.metadata["source_summaries"] == [
        {
            "source": "NVD",
            "threats": 2
        },
        {
            "source": "CISA",
            "threats": 2
        },
        {
            "source": "MITRE",
            "threats": 2
        }
    ]

@pytest.mark.integration
def test_correlation_with_real_sources(tmp_path):
    """
    Integration test using the real NVD, CISA and MITRE services.

    MITRE uses a temporary synchronization file so the real project
    synchronization state is not modified during the test.
    """

    sync_file = (
        tmp_path /
        "mitre_sync_state.json"
    )

    sync_state = MITRESyncState(
        filepath=str(sync_file)
    )

    sources = [
        NVDThreatSource(),
        CISAThreatSource(),
        MITREThreatSource(
            sync_state=sync_state
        )
    ]

    service = ThreatCorrelationService()

    correlation_result = service.collect_and_correlate(
        sources
    )

    print("\n[CORRELATION SERVICE] Real-source correlation")
    print(f"Total sources: {correlation_result.metadata['total_sources']}")
    print(f"Total input threats: {correlation_result.metadata['total_input_threats']}")
    print(f"Unique CVE IDs: {correlation_result.metadata['unique_threats']}")
    print(f"Multi-source CVEs: {correlation_result.metadata['multi_source_threats']}")

    print("\nSource summaries:")
    for summary in correlation_result.metadata["source_summaries"]:
        print(f"{summary['source']}: {summary['threats']} threat(s)")

    assert isinstance(
        correlation_result,
        ThreatCorrelationResult
    )

    assert correlation_result.metadata["total_sources"] == 3

    assert correlation_result.metadata["total_input_threats"] >= correlation_result.metadata["unique_threats"]

    assert correlation_result.metadata["unique_threats"] > 0