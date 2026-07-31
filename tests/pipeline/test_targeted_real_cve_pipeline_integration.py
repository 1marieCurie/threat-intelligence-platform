from __future__ import annotations
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from dotenv import find_dotenv, load_dotenv


load_dotenv(
    dotenv_path=find_dotenv(
        usecwd=True
    ),
    override=False,
)


import os
import re
from typing import Any
from unittest.mock import patch

import pytest
import requests

from application.services.cisa_threat_source import (
    CISAThreatSource,
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
from infrastructure.bootstrap.epss_enrichment import (
    build_epss_enrichment_service,
)


TARGET_CVE = "CVE-2021-44228"
EXPECTED_GHSA = "GHSA-jfh8-c2jp-5v3q"

REQUEST_TIMEOUT_SECONDS = 30


# ============================================================
# Targeted collection helpers
# ============================================================


def fetch_nvd_cve_by_id(
    cve_id: str,
) -> dict[str, Any]:
    """
    Récupère une CVE précise depuis NVD.

    Une stratégie de retry courte absorbe uniquement les erreurs
    réseau transitoires et les réponses serveur réessayables.
    """
    retry_policy = Retry(
        total=2,
        connect=2,
        read=2,
        status=2,
        backoff_factor=1.0,
        status_forcelist={
            429,
            500,
            502,
            503,
            504,
        },
        allowed_methods={
            "GET",
        },
        respect_retry_after_header=True,
        raise_on_status=False,
    )

    adapter = HTTPAdapter(
        max_retries=retry_policy # type: ignore
    )

    with requests.Session() as session:
        session.mount(
            "https://",
            adapter,
        )

        response = session.get(
            NVDConnector.BASE_URL,
            params={
                "cveId": cve_id,
            },
            timeout=(
                10,
                REQUEST_TIMEOUT_SECONDS,
            ),
        )

        response.raise_for_status()

        payload = response.json()

    if not isinstance(
        payload,
        dict,
    ):
        raise ValueError(
            "NVD returned an invalid JSON payload."
        )

    return payload

def build_mitre_cve_filepath(
    cve_id: str,
) -> str:
    """
    Construit le chemin cvelistV5 d'une CVE.

    Exemple :

        CVE-2021-44228
        -> cves/2021/44xxx/CVE-2021-44228.json
    """
    normalized_cve_id = (
        cve_id.strip().upper()
    )

    match = re.fullmatch(
        r"CVE-(\d{4})-(\d+)",
        normalized_cve_id,
    )

    if match is None:
        raise ValueError(
            "Invalid CVE identifier"
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
        f"{normalized_cve_id}.json"
    )


def collect_targeted_nvd_result(
    cve_id: str,
) -> CollectionResult:
    """
    Récupère et normalise une CVE depuis NVD.
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
            "total_results": (
                raw_payload.get(
                    "totalResults"
                )
            ),
            "results_per_page": (
                raw_payload.get(
                    "resultsPerPage"
                )
            ),
            "version": (
                raw_payload.get(
                    "version"
                )
            ),
            "timestamp": (
                raw_payload.get(
                    "timestamp"
                )
            ),
            "collection_mode": (
                "targeted"
            ),
        },
    )


def collect_targeted_cisa_result(
    cve_id: str,
) -> CollectionResult:
    """
    Télécharge CISA KEV et conserve uniquement la CVE ciblée.
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
            isinstance(
                vulnerability,
                dict,
            )
            and vulnerability.get(
                "cveID"
            )
            == cve_id
        )
    ]

    filtered_payload = {
        **raw_catalog,
        "vulnerabilities": (
            matching_vulnerabilities
        ),
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
            "title": raw_catalog.get(
                "title"
            ),
            "catalog_version": (
                raw_catalog.get(
                    "catalogVersion"
                )
            ),
            "date_released": (
                raw_catalog.get(
                    "dateReleased"
                )
            ),
            "matches": len(
                matching_vulnerabilities
            ),
            "collection_mode": (
                "targeted"
            ),
        },
    )


def collect_targeted_mitre_result(
    cve_id: str,
) -> CollectionResult:
    """
    Télécharge directement l'enregistrement MITRE ciblé.
    """
    connector = MITREConnector()

    source = MITREThreatSource(
        connector=connector
    )

    filepath = build_mitre_cve_filepath(
        cve_id
    )

    raw_record = (
        connector.download_cve_record(
            filepath
        )
    )

    threats = source.parse(
        [
            raw_record,
        ]
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
            "record_version": (
                raw_record.get(
                    "dataVersion"
                )
            ),
            "collection_mode": (
                "targeted"
            ),
        },
    )


def collect_targeted_github_result(
    cve_id: str,
) -> CollectionResult:
    """
    Récupère les advisories GitHub associés à une CVE.
    """
    token = (
        os.getenv(
            "GITHUB_TOKEN"
        )
        or None
    )

    connector = GitHubAdvisoryConnector(
        token=token
    )

    source = GitHubAdvisoryThreatSource(
        connector=connector
    )

    raw_advisories = (
        connector
        .fetch_advisories_by_cve_id(
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
            "authenticated": (
                token is not None
            ),
            "collection_mode": (
                "targeted"
            ),
        },
    )


# ============================================================
# Display helper
# ============================================================


def display_targeted_pipeline_result(
    correlation_result: (
        ThreatCorrelationResult
    ),
    epss_metadata: dict[str, Any],
) -> None:
    """
    Affiche un résumé du test réel ciblé.
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
        f"Target CVE           : {TARGET_CVE}"
    )

    print(
        "Unique groups        : "
        f"{len(correlation_result.groups)}"
    )

    print(
        "Multi-source groups  : "
        f"{len(
            correlation_result
            .multi_source_groups()
        )}"
    )

    group = (
        correlation_result.groups.get(
            TARGET_CVE
        )
    )

    if group is not None:
        print(
            f"Sources              : "
            f"{group.sources}"
        )

        print(
            f"Records preserved    : "
            f"{len(group.threats)}"
        )

        for source_name, threats in (
            group.threats_by_source.items()
        ):
            print(
                f"{source_name:<20}: "
                f"{len(threats)} record(s)"
            )

    print(
        "\nEPSS metadata:"
    )

    for key, value in (
        epss_metadata.items()
    ):
        print(
            f"{key:<25}: {value}"
        )


# ============================================================
# Integration test
# ============================================================


@pytest.mark.integration
@pytest.mark.external
def test_real_multi_source_synergy_for_log4shell(
) -> None:
    """
    Valide la synergie réelle autour de CVE-2021-44228.

    Sources externes :

    - NVD ;
    - CISA KEV ;
    - MITRE cvelistV5 ;
    - GitHub Advisory.

    L'enrichissement EPSS est ensuite effectué uniquement depuis
    PostgreSQL. Aucun appel FIRST n'est autorisé pendant cette étape.
    """

    # --------------------------------------------------------
    # External collection
    # --------------------------------------------------------

    nvd_result = (
        collect_targeted_nvd_result(
            TARGET_CVE
        )
    )

    cisa_result = (
        collect_targeted_cisa_result(
            TARGET_CVE
        )
    )

    mitre_result = (
        collect_targeted_mitre_result(
            TARGET_CVE
        )
    )

    github_result = (
        collect_targeted_github_result(
            TARGET_CVE
        )
    )

    collection_results = [
        nvd_result,
        cisa_result,
        mitre_result,
        github_result,
    ]

    assert len(
        nvd_result.threats
    ) >= 1, (
        "NVD did not return the target CVE."
    )

    assert len(
        cisa_result.threats
    ) >= 1, (
        "CISA KEV did not return the target CVE."
    )

    assert len(
        mitre_result.threats
    ) >= 1, (
        "MITRE did not return the target CVE."
    )

    assert len(
        github_result.threats
    ) >= 1, (
        "GitHub Advisory did not return "
        "the target CVE."
    )

    for collection_result in (
        collection_results
    ):
        for threat in (
            collection_result.threats
        ):
            assert (
                threat.id
                == TARGET_CVE
            )

    # --------------------------------------------------------
    # Correlation
    # --------------------------------------------------------

    correlation_service = (
        ThreatCorrelationService()
    )

    correlation_result = (
        correlation_service
        .correlate_results(
            collection_results
        )
    )

    assert (
        TARGET_CVE
        in correlation_result.groups
    )

    group = (
        correlation_result.groups[
            TARGET_CVE
        ]
    )

    assert group.is_multi_source is True
    assert group.source_count == 4

    expected_sources = {
        "NVD",
        "CISA",
        "MITRE",
        "github_advisory",
    }

    assert set(
        group.sources
    ) == expected_sources

    assert set(
        group.threats_by_source
    ) == expected_sources

    for source_name in expected_sources:
        assert len(
            group.threats_by_source[
                source_name
            ]
        ) >= 1

    assert len(
        group.threats
    ) >= 4

    # --------------------------------------------------------
    # Local PostgreSQL EPSS enrichment
    # --------------------------------------------------------

    epss_service = (
        build_epss_enrichment_service()
    )

    with patch(
        "requests.sessions.Session.request",
        side_effect=AssertionError(
            "EPSS enrichment must not call FIRST"
        ),
    ):
        epss_result = (
            epss_service
            .enrich_correlation_result(
                correlation_result
            )
        )

    assert (
        epss_result.metadata[
            "source"
        ]
        == "EPSS"
    )

    assert (
        epss_result.metadata[
            "storage"
        ]
        == "PostgreSQL"
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

    assert (
        epss_result.metadata[
            "missing_cves"
        ]
        == []
    )

    for threat in group.threats:
        assert (
            threat.epss_score
            is not None
        )

        assert (
            threat.epss_percentile
            is not None
        )

        assert (
            threat.epss_date
            is not None
        )

        assert (
            0.0
            <= threat.epss_score
            <= 1.0
        )

        assert (
            0.0
            <= threat.epss_percentile
            <= 1.0
        )

    # --------------------------------------------------------
    # Source-specific preservation
    # --------------------------------------------------------

    nvd_threat = (
        group.threats_by_source[
            "NVD"
        ][0]
    )

    cisa_threat = (
        group.threats_by_source[
            "CISA"
        ][0]
    )

    mitre_threat = (
        group.threats_by_source[
            "MITRE"
        ][0]
    )

    github_threat = (
        group.threats_by_source[
            "github_advisory"
        ][0]
    )

    assert nvd_threat.description
    assert (
        nvd_threat.cvss_score
        is not None
    )
    assert nvd_threat.weakness_ids
    assert nvd_threat.references

    assert cisa_threat.description

    assert (
        cisa_threat.known_exploited_date
        is not None
    )

    assert cisa_threat.remediation

    assert mitre_threat.description
    assert mitre_threat.affected_products
    assert mitre_threat.references

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
    # No destructive fusion
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
        descriptions_by_source
    ) == expected_sources

    display_targeted_pipeline_result(
        correlation_result=(
            correlation_result
        ),
        epss_metadata=(
            epss_result.metadata
        ),
    )