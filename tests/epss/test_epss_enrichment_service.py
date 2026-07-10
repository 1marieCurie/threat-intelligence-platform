from typing import Optional

import pytest
import requests

from domain.threat import Threat
from domain.collection_result import CollectionResult

from infrastructure.adapters.outbound.epss_connector import EPSSConnector

from application.services.epss_enrichment_service import (
    EPSSEnrichmentService,
    EPSSEnrichmentResult
)

from application.services.threat_correlation_service import (
    ThreatCorrelationService
)


class FakeEPSSConnector(EPSSConnector):
    """
    Fake EPSS connector used for unit tests.

    It does not call the real FIRST EPSS API.
    It returns deterministic EPSS records.
    """

    def __init__(self):
        self.calls = []

        self.fake_database = {
            "CVE-2021-44228": {
                "cve": "CVE-2021-44228",
                "epss": "0.999990000",
                "percentile": "1.000000000",
                "date": "2026-07-10"
            },
            "CVE-2024-4577": {
                "cve": "CVE-2024-4577",
                "epss": "0.999870000",
                "percentile": "0.999830000",
                "date": "2026-07-10"
            },
            "CVE-2019-19781": {
                "cve": "CVE-2019-19781",
                "epss": "0.999990000",
                "percentile": "0.999980000",
                "date": "2026-07-10"
            }
        }

    def fetch_by_batches(
        self,
        cve_ids,
        date: Optional[str] = None
    ):
        """
        Simulates EPSSConnector.fetch_by_batches().
        """

        normalized_cve_ids = [
            cve_id.strip().upper()
            for cve_id in cve_ids
            if isinstance(cve_id, str)
        ]

        self.calls.append(
            {
                "cve_ids": normalized_cve_ids,
                "date": date
            }
        )

        data = []

        for cve_id in normalized_cve_ids:
            if cve_id in self.fake_database:
                data.append(
                    self.fake_database[cve_id]
                )

        return [
            {
                "status": "OK",
                "status-code": 200,
                "total": len(data),
                "data": data
            }
        ]


def _build_unit_service():
    fake_connector = FakeEPSSConnector()

    service = EPSSEnrichmentService(
        connector=fake_connector
    )

    return service, fake_connector


def test_unit_enrich_single_threat_with_fake_connector():

    service, fake_connector = _build_unit_service()

    threat = Threat(
        id="CVE-2021-44228",
        description="Apache Log4j vulnerability"
    )

    result = service.enrich_threats(
        [threat]
    )

    print("\n[EPSS UNIT] Single Threat enrichment")
    print(f"Threat ID        : {threat.id}")
    print(f"EPSS Score       : {threat.epss_score}")
    print(f"EPSS Percentile  : {threat.epss_percentile}")
    print(f"EPSS Date        : {threat.epss_date}")

    assert isinstance(
        result,
        EPSSEnrichmentResult
    )

    assert result.metadata["source"] == "EPSS"
    assert result.metadata["requested_cves"] == 1
    assert result.metadata["epss_records_found"] == 1
    assert result.metadata["enriched_threats"] == 1
    assert result.metadata["missing_cves"] == []
    assert result.metadata["non_cve_threats"] == 0

    assert threat.epss_score == 0.99999
    assert threat.epss_percentile == 1.0
    assert threat.epss_date == "2026-07-10"

    assert len(fake_connector.calls) == 1
    assert fake_connector.calls[0]["cve_ids"] == [
        "CVE-2021-44228"
    ]


def test_unit_enrich_multiple_threats_with_fake_connector():

    service, fake_connector = _build_unit_service()

    threats = [
        Threat(
            id="CVE-2021-44228",
            description="Apache Log4j vulnerability"
        ),
        Threat(
            id="CVE-2024-4577",
            description="PHP CGI vulnerability"
        ),
        Threat(
            id="CVE-2019-19781",
            description="Citrix ADC vulnerability"
        )
    ]

    result = service.enrich_threats(
        threats
    )

    print("\n[EPSS UNIT] Multiple Threat enrichment")
    print(f"Requested CVEs      : {result.metadata['requested_cves']}")
    print(f"EPSS records found  : {result.metadata['epss_records_found']}")
    print(f"Enriched threats    : {result.metadata['enriched_threats']}")

    assert result.metadata["requested_cves"] == 3
    assert result.metadata["epss_records_found"] == 3
    assert result.metadata["enriched_threats"] == 3
    assert result.metadata["missing_cves"] == []

    for threat in threats:
        assert threat.epss_score is not None
        assert threat.epss_percentile is not None
        assert threat.epss_date == "2026-07-10"

    assert len(fake_connector.calls) == 1
    assert fake_connector.calls[0]["cve_ids"] == [
        "CVE-2021-44228",
        "CVE-2024-4577",
        "CVE-2019-19781"
    ]


def test_unit_fetch_epss_by_cve_ids_without_threat_objects():

    service, fake_connector = _build_unit_service()

    epss_lookup = service.fetch_epss_by_cve_ids(
        [
            "CVE-2021-44228",
            "CVE-2024-4577"
        ]
    )

    print("\n[EPSS UNIT] Direct CVE ID lookup")
    print(f"Records found: {len(epss_lookup)}")

    assert isinstance(
        epss_lookup,
        dict
    )

    assert "CVE-2021-44228" in epss_lookup
    assert "CVE-2024-4577" in epss_lookup

    assert epss_lookup["CVE-2021-44228"]["epss"] == "0.999990000"
    assert epss_lookup["CVE-2024-4577"]["percentile"] == "0.999830000"

    assert len(fake_connector.calls) == 1
    assert fake_connector.calls[0]["cve_ids"] == [
        "CVE-2021-44228",
        "CVE-2024-4577"
    ]


def test_unit_non_cve_threat_is_ignored_gracefully():

    service, fake_connector = _build_unit_service()

    threats = [
        Threat(
            id="GHSA-xxxx-yyyy-zzzz",
            description="Future GitHub Advisory without CVE"
        ),
        Threat(
            id="CVE-2021-44228",
            description="Apache Log4j vulnerability"
        )
    ]

    result = service.enrich_threats(
        threats
    )

    ghsa_threat = threats[0]
    cve_threat = threats[1]

    print("\n[EPSS UNIT] Non-CVE Threat handling")
    print(f"Non-CVE threats  : {result.metadata['non_cve_threats']}")
    print(f"Requested CVEs   : {result.metadata['requested_cves']}")
    print(f"Enriched threats : {result.metadata['enriched_threats']}")

    assert result.metadata["non_cve_threats"] == 1
    assert result.metadata["requested_cves"] == 1
    assert result.metadata["enriched_threats"] == 1

    assert ghsa_threat.epss_score is None
    assert ghsa_threat.epss_percentile is None
    assert ghsa_threat.epss_date is None

    assert cve_threat.epss_score == 0.99999
    assert cve_threat.epss_percentile == 1.0
    assert cve_threat.epss_date == "2026-07-10"

    assert len(fake_connector.calls) == 1
    assert fake_connector.calls[0]["cve_ids"] == [
        "CVE-2021-44228"
    ]


def test_unit_empty_threat_list_returns_empty_result():

    service, fake_connector = _build_unit_service()

    result = service.enrich_threats(
        []
    )

    print("\n[EPSS UNIT] Empty Threat list")
    print(result.metadata)

    assert isinstance(
        result,
        EPSSEnrichmentResult
    )

    assert result.threats == []
    assert result.metadata["source"] == "EPSS"
    assert result.metadata["requested_cves"] == 0
    assert result.metadata["epss_records_found"] == 0
    assert result.metadata["enriched_threats"] == 0
    assert result.metadata["missing_cves"] == []
    assert result.metadata["non_cve_threats"] == 0

    assert len(fake_connector.calls) == 0


def test_unit_duplicate_cves_are_requested_once_but_all_threats_are_enriched():

    service, fake_connector = _build_unit_service()

    threats = [
        Threat(
            id="CVE-2021-44228",
            description="NVD version"
        ),
        Threat(
            id="CVE-2021-44228",
            description="CISA version"
        ),
        Threat(
            id="cve-2021-44228",
            description="MITRE version with lowercase id"
        )
    ]

    result = service.enrich_threats(
        threats
    )

    print("\n[EPSS UNIT] Duplicate CVE handling")
    print(f"Requested CVEs   : {result.metadata['requested_cves']}")
    print(f"Enriched threats : {result.metadata['enriched_threats']}")

    assert result.metadata["requested_cves"] == 1
    assert result.metadata["enriched_threats"] == 3

    for threat in threats:
        assert threat.epss_score == 0.99999
        assert threat.epss_percentile == 1.0
        assert threat.epss_date == "2026-07-10"

    assert len(fake_connector.calls) == 1
    assert fake_connector.calls[0]["cve_ids"] == [
        "CVE-2021-44228"
    ]


def test_unit_missing_cve_is_reported_in_metadata():

    service, fake_connector = _build_unit_service()

    threats = [
        Threat(
            id="CVE-2021-44228",
            description="Known in fake EPSS database"
        ),
        Threat(
            id="CVE-2099-0001",
            description="Not found in fake EPSS database"
        )
    ]

    result = service.enrich_threats(
        threats
    )

    known_threat = threats[0]
    missing_threat = threats[1]

    print("\n[EPSS UNIT] Missing CVE handling")
    print(f"Requested CVEs      : {result.metadata['requested_cves']}")
    print(f"EPSS records found  : {result.metadata['epss_records_found']}")
    print(f"Enriched threats    : {result.metadata['enriched_threats']}")
    print(f"Missing CVEs        : {result.metadata['missing_cves']}")

    assert result.metadata["requested_cves"] == 2
    assert result.metadata["epss_records_found"] == 1
    assert result.metadata["enriched_threats"] == 1
    assert result.metadata["missing_cves"] == [
        "CVE-2099-0001"
    ]

    assert known_threat.epss_score == 0.99999

    assert missing_threat.epss_score is None
    assert missing_threat.epss_percentile is None
    assert missing_threat.epss_date is None

    assert len(fake_connector.calls) == 1


def test_unit_enrich_correlation_result_with_fake_connector():

    service, fake_connector = _build_unit_service()

    nvd_result = CollectionResult(
        threats=[
            Threat(
                id="CVE-2021-44228",
                description="NVD description"
            )
        ],
        metadata={
            "source": "NVD"
        }
    )

    cisa_result = CollectionResult(
        threats=[
            Threat(
                id="CVE-2021-44228",
                description="CISA description"
            )
        ],
        metadata={
            "source": "CISA"
        }
    )

    correlation_service = ThreatCorrelationService()

    correlation_result = correlation_service.correlate_results(
        [
            nvd_result,
            cisa_result
        ]
    )

    epss_result = service.enrich_correlation_result(
        correlation_result
    )

    group = correlation_result.groups[
        "CVE-2021-44228"
    ]

    print("\n[EPSS UNIT] Correlation result enrichment")
    print(f"Group ID         : {group.id}")
    print(f"Group sources    : {group.sources}")
    print(f"Threats in group : {len(group.threats)}")
    print(f"Enriched threats : {epss_result.metadata['enriched_threats']}")

    assert epss_result.metadata["requested_cves"] == 1
    assert epss_result.metadata["enriched_threats"] == 2

    for threat in group.threats:
        assert threat.epss_score == 0.99999
        assert threat.epss_percentile == 1.0
        assert threat.epss_date == "2026-07-10"

    assert len(fake_connector.calls) == 1
    assert fake_connector.calls[0]["cve_ids"] == [
        "CVE-2021-44228"
    ]


def test_unit_invalid_cve_ids_return_empty_lookup():

    service, fake_connector = _build_unit_service()

    epss_lookup = service.fetch_epss_by_cve_ids(
        [
            "",
            None,
            "INVALID-ID",
            "GHSA-xxxx-yyyy-zzzz"
        ]
    )

    print("\n[EPSS UNIT] Invalid CVE ID lookup")
    print(epss_lookup)

    assert epss_lookup == {}

    assert len(fake_connector.calls) == 0


@pytest.mark.integration
def test_integration_enrich_single_threat_with_real_epss_api():

    service = EPSSEnrichmentService()

    threat = Threat(
        id="CVE-2021-44228",
        description="Apache Log4j vulnerability"
    )

    try:
        result = service.enrich_threats(
            [threat]
        )

    except requests.exceptions.RequestException as error:
        pytest.skip(
            f"Skipping EPSS integration test due to external API/network issue: {error}"
        )

    print("\n[EPSS INTEGRATION] Real API enrichment")
    print(f"Threat ID        : {threat.id}")
    print(f"EPSS Score       : {threat.epss_score}")
    print(f"EPSS Percentile  : {threat.epss_percentile}")
    print(f"EPSS Date        : {threat.epss_date}")

    assert result.metadata["source"] == "EPSS"
    assert result.metadata["requested_cves"] == 1
    assert result.metadata["epss_records_found"] >= 1
    assert result.metadata["enriched_threats"] == 1

    assert threat.epss_score is not None
    assert threat.epss_percentile is not None
    assert threat.epss_date is not None

    assert isinstance(threat.epss_score, float)
    assert isinstance(threat.epss_percentile, float)
    assert isinstance(threat.epss_date, str)

    assert 0 <= threat.epss_score <= 1
    assert 0 <= threat.epss_percentile <= 1