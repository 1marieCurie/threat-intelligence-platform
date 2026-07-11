from __future__ import annotations

import os
import re
from typing import Any

import pytest
import requests

from application.services.cisa_threat_source import (
    CISAThreatSource,
)
from application.services.epss_enrichment_service import (
    EPSSEnrichmentService,
)
from application.services.github_advisory_threat_source import (
    GitHubAdvisoryThreatSource,
)
from application.services.mitre_threat_source import (
    MITREThreatSource,
)
from application.services.nvd_threat_source import (
    NVDThreatSource,
)
from application.services.threat_correlation_service import (
    ThreatCorrelationResult,
    ThreatCorrelationService,
)
from domain.collection_result import CollectionResult
from domain.threat import Threat
from infrastructure.adapters.outbound.github_advisory_connector import (
    GitHubAdvisoryConnector,
)
from infrastructure.adapters.outbound.mitre_connector import (
    MITREConnector,
)
from infrastructure.adapters.outbound.nvd_connector import (
    NVDConnector,
)


TARGET_CVE = "CVE-2021-44228"
EXPECTED_GHSA = "GHSA-jfh8-c2jp-5v3q"

REQUEST_TIMEOUT = 30


# ============================================================
# Targeted collection helpers
# ============================================================


def fetch_nvd_cve_by_id(
    cve_id: str,
) -> dict[str, Any]:
    """
    Retrieve one precise CVE from the real NVD API.

    NVDConnector currently supports date-window collection only.
    This helper uses the same connector endpoint with the NVD
    cveId filter until fetch_by_cve_id() is added to the connector.
    """

    response = requests.get(
        NVDConnector.BASE_URL,
        params={
            "cveId": cve_id,
        },
        timeout=REQUEST_TIMEOUT,
    )

    response.raise_for_status()

    payload = response.json()

    if not isinstance(payload, dict):
        raise ValueError(
            "NVD returned an invalid JSON payload."
        )

    return payload


def build_mitre_cve_filepath(
    cve_id: str,
) -> str:
    """
    Build the cvelistV5 repository path for a CVE identifier.

    Examples:

        CVE-2026-0964
        -> cves/2026/0xxx/CVE-2026-0964.json

        CVE-2021-44228
        -> cves/2021/44xxx/CVE-2021-44228.json
    """

    match = re.fullmatch(
        r"CVE-(\d{4})-(\d+)",
        cve_id.strip().upper(),
    )

    if match is None:
        raise ValueError(
            f"Invalid CVE identifier: {cve_id}"
        )

    year = match.group(1)
    sequence = match.group(2)

    if len(sequence) <= 3:
        directory = "0xxx"
    else:
        directory = (
            sequence[:-3]
            + "xxx"
        )

    return (
        f"cves/{year}/{directory}/"
        f"{cve_id.strip().upper()}.json"
    )


def collect_targeted_nvd_result(
    cve_id: str,
) -> CollectionResult:
    """
    Retrieve and parse one real CVE from NVD.
    """

    source = NVDThreatSource()

    raw_payload = fetch_nvd_cve_by_id(
        cve_id
    )

    threats = source.parse(
        raw_payload
    )

    targeted_threats = [
        threat
        for threat in threats
        if threat.id == cve_id
    ]

    return CollectionResult(
        threats=targeted_threats,
        metadata={
            "source": source.name(),
            "target_cve": cve_id,
            "total_results": raw_payload.get(
                "totalResults"
            ),
            "results_per_page": raw_payload.get(
                "resultsPerPage"
            ),
            "version": raw_payload.get(
                "version"
            ),
            "timestamp": raw_payload.get(
                "timestamp"
            ),
            "collection_mode": "targeted",
        },
    )


def collect_targeted_cisa_result(
    cve_id: str,
) -> CollectionResult:
    """
    Download the real CISA KEV catalog and retain only the
    requested CVE before parsing.
    """

    source = CISAThreatSource()

    raw_catalog = source.fetch_raw()

    matching_vulnerabilities = [
        vulnerability
        for vulnerability in raw_catalog.get(
            "vulnerabilities",
            [],
        )
        if (
            isinstance(vulnerability, dict)
            and vulnerability.get("cveID") == cve_id
        )
    ]

    filtered_payload = {
        **raw_catalog,
        "vulnerabilities": matching_vulnerabilities,
        "count": len(
            matching_vulnerabilities
        ),
    }

    threats = source.parse(
        filtered_payload
    )

    return CollectionResult(
        threats=threats,
        metadata={
            "source": source.name(),
            "target_cve": cve_id,
            "title": raw_catalog.get("title"),
            "catalog_version": raw_catalog.get(
                "catalogVersion"
            ),
            "date_released": raw_catalog.get(
                "dateReleased"
            ),
            "matches": len(
                matching_vulnerabilities
            ),
            "collection_mode": "targeted",
        },
    )


def collect_targeted_mitre_result(
    cve_id: str,
) -> CollectionResult:
    """
    Download one precise real CVE Record from the MITRE
    cvelistV5 repository and parse it directly.

    This bypasses incremental synchronization because this test
    targets one known historical vulnerability.
    """

    connector = MITREConnector()

    source = MITREThreatSource(
        connector=connector
    )

    filepath = build_mitre_cve_filepath(
        cve_id
    )

    raw_record = connector.download_cve_record(
        filepath
    )

    threats = source.parse(
        [raw_record]
    )

    targeted_threats = [
        threat
        for threat in threats
        if threat.id == cve_id
    ]

    return CollectionResult(
        threats=targeted_threats,
        metadata={
            "source": source.name(),
            "target_cve": cve_id,
            "filepath": filepath,
            "record_version": raw_record.get(
                "dataVersion"
            ),
            "collection_mode": "targeted",
        },
    )


def collect_targeted_github_result(
    cve_id: str,
) -> CollectionResult:
    """
    Retrieve and parse all real GitHub reviewed advisories
    associated with the requested CVE.
    """

    token = os.getenv(
        "GITHUB_TOKEN"
    )

    connector = GitHubAdvisoryConnector(
        token=token
    )

    source = GitHubAdvisoryThreatSource(
        connector=connector
    )

    raw_advisories = (
        connector.fetch_advisories_by_cve_id(
            cve_id
        )
    )

    threats = source.parse(
        raw_advisories
    )

    targeted_threats = [
        threat
        for threat in threats
        if (
            threat.id == cve_id
            or cve_id
            in threat.external_ids.get(
                "CVE",
                [],
            )
        )
    ]

    return CollectionResult(
        threats=targeted_threats,
        metadata={
            "source": source.name(),
            "target_cve": cve_id,
            "advisories_found": len(
                raw_advisories
            ),
            "threats_parsed": len(
                targeted_threats
            ),
            "authenticated": token is not None,
            "collection_mode": "targeted",
        },
    )


# ============================================================
# Display helpers
# ============================================================


def truncate(
    value: str | None,
    max_length: int = 250,
) -> str:
    """
    Truncate long text for readable test output.
    """

    if not value:
        return "N/A"

    if len(value) <= max_length:
        return value

    return (
        value[:max_length]
        + "..."
    )


def display_threat(
    source_name: str,
    threat: Threat,
) -> None:
    """
    Display one source-specific Threat object.
    """

    print(
        f"\n---------------- {source_name} ----------------"
    )

    print(
        f"ID                    : {threat.id}"
    )

    print(
        f"External IDs          : "
        f"{threat.external_ids or 'N/A'}"
    )

    print(
        f"Title                 : "
        f"{threat.title or 'N/A'}"
    )

    print(
        f"Description           : "
        f"{truncate(threat.description)}"
    )

    print(
        f"Advisory type         : "
        f"{threat.advisory_type or 'N/A'}"
    )

    print(
        f"Severity              : "
        f"{threat.severity or 'N/A'}"
    )

    print(
        f"CVSS score            : "
        f"{threat.cvss_score if threat.cvss_score is not None else 'N/A'}"
    )

    print(
        f"EPSS score            : "
        f"{threat.epss_score if threat.epss_score is not None else 'N/A'}"
    )

    print(
        f"EPSS percentile       : "
        f"{threat.epss_percentile if threat.epss_percentile is not None else 'N/A'}"
    )

    print(
        f"EPSS date             : "
        f"{threat.epss_date or 'N/A'}"
    )

    print(
        f"Known exploited date : "
        f"{threat.known_exploited_date or 'N/A'}"
    )

    print(
        f"Ransomware use        : "
        f"{threat.ransomware_campaign_use or 'N/A'}"
    )

    print(
        f"Remediation           : "
        f"{truncate(threat.remediation)}"
    )

    print(
        f"Published             : "
        f"{threat.published_date or 'N/A'}"
    )

    print(
        f"Last modified         : "
        f"{threat.last_modified_date or 'N/A'}"
    )

    print(
        f"Weaknesses            : "
        f"{threat.weaknesses or 'N/A'}"
    )

    print(
        f"Products              : "
        f"{len(threat.affected_products)}"
    )

    for index, product in enumerate(
        threat.affected_products,
        start=1,
    ):
        print(
            f"  Product #{index}: {product}"
        )

    print(
        f"References            : "
        f"{len(threat.references)}"
    )

    for reference in threat.references[:5]:
        print(
            f"  - {reference}"
        )

    if len(threat.references) > 5:
        print(
            f"  ... "
            f"{len(threat.references) - 5} more"
        )


def display_targeted_pipeline_result(
    correlation_result: ThreatCorrelationResult,
    epss_metadata: dict[str, Any],
) -> None:
    """
    Display the final real multi-source synergy result.
    """

    print(
        "\n"
        "=================================================="
    )
    print(
        "       TARGETED REAL CVE PIPELINE TEST"
    )
    print(
        "=================================================="
    )

    print(
        f"\nTarget CVE            : {TARGET_CVE}"
    )

    print(
        f"Unique groups         : "
        f"{len(correlation_result.groups)}"
    )

    print(
        f"Multi-source groups   : "
        f"{len(correlation_result.multi_source_groups())}"
    )

    print(
        "\n----- Correlation metadata -----"
    )

    for key, value in (
        correlation_result.metadata.items()
    ):
        print(
            f"{key:<25}: {value}"
        )

    group = correlation_result.groups.get(
        TARGET_CVE
    )

    if group is None:
        print(
            "\nTarget CVE was not correlated."
        )
        return

    print(
        "\n----- Target correlation group -----"
    )

    print(
        f"Threat ID             : {group.id}"
    )

    print(
        f"Sources               : {group.sources}"
    )

    print(
        f"Source count          : {group.source_count}"
    )

    print(
        f"Records preserved     : {len(group.threats)}"
    )

    for source_name, threats in (
        group.threats_by_source.items()
    ):
        for threat in threats:
            display_threat(
                source_name=source_name,
                threat=threat,
            )

    print(
        "\n---------------- EPSS ----------------"
    )

    for key, value in epss_metadata.items():
        print(
            f"{key:<25}: {value}"
        )


# ============================================================
# Main targeted integration test
# ============================================================


@pytest.mark.integration
def test_real_multi_source_synergy_for_log4shell() -> None:
    """
    Validate real multi-source synergy for CVE-2021-44228.

    Real sources involved:

    - NVD
    - CISA KEV
    - MITRE cvelistV5
    - GitHub Global Security Advisories
    - EPSS

    Expected behavior:

    - each primary source returns the same CVE;
    - each source-specific Threat object remains separate;
    - correlation groups the records by CVE identifier;
    - EPSS enriches every correlated record;
    - no field-level fusion is performed.
    """

    # --------------------------------------------------------
    # Real targeted collection
    # --------------------------------------------------------

    nvd_result = collect_targeted_nvd_result(
        TARGET_CVE
    )

    cisa_result = collect_targeted_cisa_result(
        TARGET_CVE
    )

    mitre_result = collect_targeted_mitre_result(
        TARGET_CVE
    )

    github_result = collect_targeted_github_result(
        TARGET_CVE
    )

    collection_results = [
        nvd_result,
        cisa_result,
        mitre_result,
        github_result,
    ]

    # --------------------------------------------------------
    # Validate each real source independently
    # --------------------------------------------------------

    assert len(nvd_result.threats) >= 1, (
        f"NVD did not return {TARGET_CVE}."
    )

    assert len(cisa_result.threats) >= 1, (
        f"CISA KEV did not return {TARGET_CVE}."
    )

    assert len(mitre_result.threats) >= 1, (
        f"MITRE did not return {TARGET_CVE}."
    )

    assert len(github_result.threats) >= 1, (
        f"GitHub Advisory did not return {TARGET_CVE}."
    )

    for result in collection_results:
        for threat in result.threats:
            assert threat.id == TARGET_CVE

    # --------------------------------------------------------
    # Real correlation
    # --------------------------------------------------------

    correlation_service = (
        ThreatCorrelationService()
    )

    correlation_result = (
        correlation_service.correlate_results(
            collection_results
        )
    )

    assert TARGET_CVE in (
        correlation_result.groups
    )

    group = correlation_result.groups[
        TARGET_CVE
    ]

    assert group.is_multi_source is True

    assert group.source_count == 4

    assert set(group.sources) == {
        "NVD",
        "CISA",
        "MITRE",
        "github_advisory",
    }

    assert set(
        group.threats_by_source.keys()
    ) == {
        "NVD",
        "CISA",
        "MITRE",
        "github_advisory",
    }

    assert len(
        group.threats_by_source["NVD"]
    ) >= 1

    assert len(
        group.threats_by_source["CISA"]
    ) >= 1

    assert len(
        group.threats_by_source["MITRE"]
    ) >= 1

    assert len(
        group.threats_by_source[
            "github_advisory"
        ]
    ) >= 1

    # At least one record from each primary source.
    assert len(group.threats) >= 4

    # --------------------------------------------------------
    # Real EPSS enrichment
    # --------------------------------------------------------

    epss_service = (
        EPSSEnrichmentService()
    )

    epss_result = (
        epss_service.enrich_correlation_result(
            correlation_result
        )
    )

    assert (
        epss_result.metadata[
            "requested_cves"
        ]
        == 1
    )

    assert (
        epss_result.metadata[
            "epss_records_found"
        ]
        == 1
    )

    assert (
        epss_result.metadata[
            "enriched_threats"
        ]
        == len(group.threats)
    )

    for threat in group.threats:
        assert threat.epss_score is not None
        assert threat.epss_percentile is not None
        assert threat.epss_date is not None

    # --------------------------------------------------------
    # Validate source-specific preservation
    # --------------------------------------------------------

    nvd_threat = (
        group.threats_by_source["NVD"][0]
    )

    cisa_threat = (
        group.threats_by_source["CISA"][0]
    )

    mitre_threat = (
        group.threats_by_source["MITRE"][0]
    )

    github_threat = (
        group.threats_by_source[
            "github_advisory"
        ][0]
    )

    # NVD provides severity and CVSS information.
    assert nvd_threat.description
    assert nvd_threat.cvss_score is not None
    assert nvd_threat.weaknesses
    assert nvd_threat.references

    # CISA confirms known exploitation and remediation.
    assert cisa_threat.description

    assert (
        cisa_threat.known_exploited_date
        is not None
    )

    assert cisa_threat.remediation

    # MITRE preserves CNA and optional ADP information.
    assert mitre_threat.description
    assert mitre_threat.affected_products
    assert mitre_threat.references

    # GitHub preserves GHSA and package-specific information.
    assert github_threat.description

    assert EXPECTED_GHSA in (
        github_threat.external_ids.get(
            "GHSA",
            [],
        )
    )

    assert github_threat.affected_products
    assert github_threat.references

    # --------------------------------------------------------
    # Confirm that no destructive fusion occurred
    # --------------------------------------------------------

    assert (
        nvd_threat
        is not cisa_threat
    )

    assert (
        nvd_threat
        is not mitre_threat
    )

    assert (
        nvd_threat
        is not github_threat
    )

    descriptions_by_source = {
        source_name: [
            threat.description
            for threat in threats
        ]
        for source_name, threats
        in group.threats_by_source.items()
    }

    assert set(
        descriptions_by_source.keys()
    ) == {
        "NVD",
        "CISA",
        "MITRE",
        "github_advisory",
    }

    # --------------------------------------------------------
    # Detailed output
    # --------------------------------------------------------

    display_targeted_pipeline_result(
        correlation_result=correlation_result,
        epss_metadata=epss_result.metadata,
    )
