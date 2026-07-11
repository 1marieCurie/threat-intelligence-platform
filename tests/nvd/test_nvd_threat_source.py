from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from application.services.nvd_threat_source import (
    NVDThreatSource,
)
from domain.threat import Threat
from infrastructure.adapters.outbound.nvd_connector import (
    NVDConnector,
)


# ============================================================
# Fake NVD data
# ============================================================


@pytest.fixture
def sample_cve() -> dict[str, Any]:
    """
    Return a realistic CVE payload compatible with the current
    NVDThreatSource parser.

    No network request is performed.
    """

    return {
        "id": "CVE-2026-12345",
        "sourceIdentifier": "security@example.org",
        "published": "2026-07-01T10:00:00.000",
        "lastModified": "2026-07-02T12:00:00.000",
        "vulnStatus": "Analyzed",
        "descriptions": [
            {
                "lang": "en",
                "value": (
                    "A remote code execution vulnerability affects "
                    "Example Product before version 2.0.0."
                ),
            },
            {
                "lang": "fr",
                "value": (
                    "Une vulnérabilité d'exécution de code à "
                    "distance affecte Example Product."
                ),
            },
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "cvssData": {
                        "version": "3.1",
                        "vectorString": (
                            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/"
                            "S:U/C:H/I:H/A:H"
                        ),
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                        "attackVector": "NETWORK",
                        "attackComplexity": "LOW",
                        "privilegesRequired": "NONE",
                        "userInteraction": "NONE",
                        "scope": "UNCHANGED",
                        "confidentialityImpact": "HIGH",
                        "integrityImpact": "HIGH",
                        "availabilityImpact": "HIGH",
                    },
                    "exploitabilityScore": 3.9,
                    "impactScore": 5.9,
                }
            ]
        },
        "weaknesses": [
            {
                "source": "nvd@nist.gov",
                "type": "Primary",
                "description": [
                    {
                        "lang": "en",
                        "value": "CWE-78",
                    }
                ],
            }
        ],
        "references": [
            {
                "url": (
                    "https://example.org/advisory/"
                    "CVE-2026-12345"
                ),
                "source": "security@example.org",
                "tags": [
                    "Vendor Advisory",
                ],
            },
            {
                "url": (
                    "https://example.org/patch/"
                    "CVE-2026-12345"
                ),
                "source": "security@example.org",
                "tags": [
                    "Patch",
                ],
            },
        ],

        # Structure expected by _extract_affected_products():
        #
        # affected[]
        #   └── affectedData[]
        "affected": [
            {
                "source": "nvd@nist.gov",
                "affectedData": [
                    {
                        "vendor": "Example Vendor",
                        "product": "Example Product",
                        "platforms": [
                            "Windows",
                            "Linux",
                        ],
                        "versions": [
                            {
                                "version": "1.0.0",
                                "status": "affected",
                            },
                            {
                                "version": "1.9.9",
                                "status": "affected",
                            },
                            {
                                "version": "2.0.0",
                                "status": "unaffected",
                            },
                        ],
                    }
                ],
            }
        ],
    }


@pytest.fixture
def sample_nvd_response(
    sample_cve: dict[str, Any],
) -> dict[str, Any]:
    """
    Return a fake complete NVD API response.
    """

    return {
        "resultsPerPage": 1,
        "startIndex": 0,
        "totalResults": 1,
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": "2026-07-02T15:00:00.000",
        "vulnerabilities": [
            {
                "cve": deepcopy(sample_cve),
            }
        ],
    }


# ============================================================
# Unit tests: no network access
# ============================================================


def test_source_name() -> None:
    source = NVDThreatSource()

    assert source.name() == "NVD"


def test_parse_complete_cve(
    sample_cve: dict[str, Any],
) -> None:
    """
    Verify complete mapping of one NVD CVE to Threat.
    """

    source = NVDThreatSource()

    threat = source._parse_cve(
        deepcopy(sample_cve)
    )

    assert isinstance(threat, Threat)

    # Identity
    assert threat.id == "CVE-2026-12345"

    # Description
    assert threat.description == (
        "A remote code execution vulnerability affects "
        "Example Product before version 2.0.0."
    )

    # CVSS
    assert threat.severity == "CRITICAL"
    assert threat.cvss_score == 9.8

    # CWE
    assert threat.weaknesses == [
        "CWE-78",
    ]

    # References
    assert threat.references == [
        (
            "https://example.org/advisory/"
            "CVE-2026-12345"
        ),
        (
            "https://example.org/patch/"
            "CVE-2026-12345"
        ),
    ]

    # Dates
    assert threat.published_date == (
        "2026-07-01T10:00:00.000"
    )

    assert threat.last_modified_date == (
        "2026-07-02T12:00:00.000"
    )

    # Affected products
    assert len(threat.affected_products) == 1

    assert threat.affected_products[0] == {
        "vendor": "Example Vendor",
        "product": "Example Product",
        "platforms": [
            "Windows",
            "Linux",
        ],
        "versions": [
            {
                "version": "1.0.0",
                "status": "affected",
            },
            {
                "version": "1.9.9",
                "status": "affected",
            },
            {
                "version": "2.0.0",
                "status": "unaffected",
            },
        ],
    }

    # Raw source preservation
    assert threat.raw == sample_cve


def test_description_prefers_english(
    sample_cve: dict[str, Any],
) -> None:
    source = NVDThreatSource()

    threat = source._parse_cve(
        deepcopy(sample_cve)
    )

    assert threat.description.startswith(
        "A remote code execution vulnerability"
    )


def test_description_falls_back_to_first_language(
    sample_cve: dict[str, Any],
) -> None:
    source = NVDThreatSource()

    cve = deepcopy(sample_cve)

    cve["descriptions"] = [
        {
            "lang": "fr",
            "value": "Description française.",
        },
        {
            "lang": "es",
            "value": "Descripción española.",
        },
    ]

    threat = source._parse_cve(cve)

    assert threat.description == (
        "Description française."
    )


def test_description_replaces_non_breaking_spaces(
    sample_cve: dict[str, Any],
) -> None:
    source = NVDThreatSource()

    cve = deepcopy(sample_cve)

    cve["descriptions"] = [
        {
            "lang": "en",
            "value": (
                "Example\u00a0description\u00a0with spaces."
            ),
        }
    ]

    threat = source._parse_cve(cve)

    assert threat.description == (
        "Example description with spaces."
    )


def test_missing_metrics(
    sample_cve: dict[str, Any],
) -> None:
    """
    Missing metrics must not prevent parsing.
    """

    source = NVDThreatSource()

    cve = deepcopy(sample_cve)
    cve.pop("metrics", None)

    threat = source._parse_cve(cve)

    print("\n========== NO METRICS ==========")
    print("Severity :", threat.severity)
    print("CVSS     :", threat.cvss_score)

    assert threat.severity is None
    assert threat.cvss_score is None


def test_missing_references(
    sample_cve: dict[str, Any],
) -> None:
    """
    Missing references must produce an empty list.
    """

    source = NVDThreatSource()

    cve = deepcopy(sample_cve)
    cve.pop("references", None)

    threat = source._parse_cve(cve)

    print("\n========== NO REFERENCES ==========")
    print(threat.references)

    assert threat.references == []


def test_missing_weaknesses(
    sample_cve: dict[str, Any],
) -> None:
    """
    Missing weaknesses must produce an empty list.
    """

    source = NVDThreatSource()

    cve = deepcopy(sample_cve)
    cve.pop("weaknesses", None)

    threat = source._parse_cve(cve)

    print("\n========== NO WEAKNESSES ==========")
    print(threat.weaknesses)

    assert threat.weaknesses == []


def test_missing_affected_products(
    sample_cve: dict[str, Any],
) -> None:
    """
    Missing affected data must produce an empty list.
    """

    source = NVDThreatSource()

    cve = deepcopy(sample_cve)
    cve.pop("affected", None)

    threat = source._parse_cve(cve)

    print("\n========== NO AFFECTED PRODUCTS ==========")
    print(threat.affected_products)

    assert threat.affected_products == []


def test_affected_vendor_na_becomes_none(
    sample_cve: dict[str, Any],
) -> None:
    source = NVDThreatSource()

    cve = deepcopy(sample_cve)

    affected_data = cve["affected"][0]["affectedData"][0]
    affected_data["vendor"] = "n/a"

    threat = source._parse_cve(cve)

    assert threat.affected_products[0]["vendor"] is None


def test_affected_product_na_becomes_none(
    sample_cve: dict[str, Any],
) -> None:
    source = NVDThreatSource()

    cve = deepcopy(sample_cve)

    affected_data = cve["affected"][0]["affectedData"][0]
    affected_data["product"] = "n/a"

    threat = source._parse_cve(cve)

    assert threat.affected_products[0]["product"] is None


def test_missing_descriptions(
    sample_cve: dict[str, Any],
) -> None:
    """
    Missing descriptions must produce an empty string.
    """

    source = NVDThreatSource()

    cve = deepcopy(sample_cve)
    cve.pop("descriptions", None)

    threat = source._parse_cve(cve)

    assert threat.description == ""


def test_missing_cve_identifier_raises_value_error(
    sample_cve: dict[str, Any],
) -> None:
    """
    A CVE without an identifier is invalid.
    """

    source = NVDThreatSource()

    cve = deepcopy(sample_cve)
    cve.pop("id", None)

    with pytest.raises(
        ValueError,
        match="Missing CVE identifier",
    ):
        source._parse_cve(cve)


def test_parse_fake_nvd_response(
    sample_nvd_response: dict[str, Any],
) -> None:
    """
    Verify parsing of a complete fake NVD response.
    """

    source = NVDThreatSource()

    threats = source.parse(
        deepcopy(sample_nvd_response)
    )

    assert isinstance(threats, list)
    assert len(threats) == 1

    threat = threats[0]

    assert isinstance(threat, Threat)
    assert threat.id == "CVE-2026-12345"
    assert threat.cvss_score == 9.8
    assert len(threat.affected_products) == 1


def test_parse_multiple_fake_cves(
    sample_cve: dict[str, Any],
) -> None:
    """
    Verify parsing of several valid NVD items.
    """

    second_cve = deepcopy(sample_cve)

    second_cve["id"] = "CVE-2026-54321"
    second_cve["descriptions"][0]["value"] = (
        "A second example vulnerability."
    )

    raw = {
        "vulnerabilities": [
            {
                "cve": deepcopy(sample_cve),
            },
            {
                "cve": second_cve,
            },
        ]
    }

    source = NVDThreatSource()

    threats = source.parse(raw)

    assert len(threats) == 2

    assert [
        threat.id
        for threat in threats
    ] == [
        "CVE-2026-12345",
        "CVE-2026-54321",
    ]


def test_parse_empty_vulnerabilities() -> None:
    """
    An empty NVD response must produce an empty list.
    """

    source = NVDThreatSource()

    raw = {
        "resultsPerPage": 0,
        "startIndex": 0,
        "totalResults": 0,
        "format": "NVD_CVE",
        "version": "2.0",
        "timestamp": "2026-07-02T15:00:00.000",
        "vulnerabilities": [],
    }

    threats = source.parse(raw)

    assert threats == []


def test_parse_missing_vulnerabilities_key() -> None:
    """
    A response without vulnerabilities must produce an empty list.
    """

    source = NVDThreatSource()

    threats = source.parse({})

    assert threats == []


# ============================================================
# CVSS unit tests
# ============================================================


@pytest.mark.parametrize(
    ("metric_name", "version", "score", "severity"),
    [
        (
            "cvssMetricV40",
            "4.0",
            9.3,
            "CRITICAL",
        ),
        (
            "cvssMetricV31",
            "3.1",
            9.8,
            "CRITICAL",
        ),
        (
            "cvssMetricV30",
            "3.0",
            8.8,
            "HIGH",
        ),
    ],
)
def test_extract_cvss_v3_and_v4(
    sample_cve: dict[str, Any],
    metric_name: str,
    version: str,
    score: float,
    severity: str,
) -> None:
    source = NVDThreatSource()

    cve = deepcopy(sample_cve)

    cve["metrics"] = {
        metric_name: [
            {
                "source": "nvd@nist.gov",
                "type": "Primary",
                "cvssData": {
                    "version": version,
                    "baseScore": score,
                    "baseSeverity": severity,
                },
            }
        ]
    }

    assert source._extract_cvss(cve) == score
    assert source._extract_severity(cve) == severity


def test_extract_cvss_v2(
    sample_cve: dict[str, Any],
) -> None:
    source = NVDThreatSource()

    cve = deepcopy(sample_cve)

    cve["metrics"] = {
        "cvssMetricV2": [
            {
                "source": "nvd@nist.gov",
                "type": "Primary",
                "cvssData": {
                    "version": "2.0",
                    "baseScore": 7.5,
                },
                "baseSeverity": "HIGH",
            }
        ]
    }

    assert source._extract_cvss(cve) == 7.5
    assert source._extract_severity(cve) == "HIGH"


def test_cvss_priority_prefers_v4(
    sample_cve: dict[str, Any],
) -> None:
    source = NVDThreatSource()

    cve = deepcopy(sample_cve)

    cve["metrics"] = {
        "cvssMetricV31": [
            {
                "cvssData": {
                    "version": "3.1",
                    "baseScore": 10.0,
                    "baseSeverity": "CRITICAL",
                }
            }
        ],
        "cvssMetricV40": [
            {
                "cvssData": {
                    "version": "4.0",
                    "baseScore": 9.3,
                    "baseSeverity": "CRITICAL",
                }
            }
        ],
    }

    assert source._extract_cvss(cve) == 9.3
    assert source._extract_severity(cve) == "CRITICAL"


# ============================================================
# Integration helpers
# ============================================================


def fetch_real_period(
    *,
    start_date: str,
    end_date: str,
    results_per_page: int = 5,
) -> dict[str, Any]:
    """
    Fetch a real NVD period.

    This helper performs an HTTP request and must only be called
    from integration tests.
    """

    connector = NVDConnector()

    return connector.fetch(
        start_date=start_date,
        end_date=end_date,
        results_per_page=results_per_page,
        start_index=0,
    )


def print_period_result(
    *,
    raw: dict[str, Any],
    title: str,
) -> list[Threat]:
    """
    Parse and display a real NVD response.
    """

    print(f"\n========== {title} ==========")

    source = NVDThreatSource()
    threats = source.parse(raw)

    print(f"Threats parsed : {len(threats)}")

    for threat in threats:
        print("--------------------------------")
        print(f"ID          : {threat.id}")
        print(f"Severity    : {threat.severity}")
        print(f"CVSS Score  : {threat.cvss_score}")

    return threats


# ============================================================
# Integration tests: real NVD API
# ============================================================


@pytest.mark.integration
def test_integration_fetch_recent_nvd_cves() -> None:
    raw = fetch_real_period(
        start_date="2026-06-29T00:00:00.000Z",
        end_date="2026-07-06T00:00:00.000Z",
        results_per_page=5,
    )

    threats = print_period_result(
        raw=raw,
        title="Recent CVEs with CVSS v3.1 or v4.0",
    )

    assert isinstance(raw, dict)
    assert "vulnerabilities" in raw
    assert len(threats) >= 1

    for threat in threats:
        assert isinstance(threat, Threat)
        assert threat.id.startswith("CVE-")


@pytest.mark.integration
def test_integration_fetch_cvss_v30_period() -> None:
    raw = fetch_real_period(
        start_date="2018-01-01T00:00:00.000Z",
        end_date="2018-01-31T23:59:59.000Z",
        results_per_page=5,
    )

    threats = print_period_result(
        raw=raw,
        title="Historical CVEs with CVSS v3.0",
    )

    assert len(threats) >= 1

    for threat in threats:
        assert isinstance(threat, Threat)
        assert threat.id.startswith("CVE-")


@pytest.mark.integration
def test_integration_fetch_cvss_v20_period() -> None:
    raw = fetch_real_period(
        start_date="2009-01-01T00:00:00.000Z",
        end_date="2009-01-31T23:59:59.000Z",
        results_per_page=5,
    )

    threats = print_period_result(
        raw=raw,
        title="Historical CVEs with CVSS v2.0",
    )

    assert len(threats) >= 1

    for threat in threats:
        assert isinstance(threat, Threat)
        assert threat.id.startswith("CVE-")


@pytest.mark.integration
def test_integration_real_nvd_missing_fields() -> None:
    raw = fetch_real_period(
        start_date="2026-06-29T00:00:00.000Z",
        end_date="2026-07-06T00:00:00.000Z",
        results_per_page=1,
    )

    vulnerabilities = raw.get(
        "vulnerabilities",
        [],
    )

    assert vulnerabilities, (
        "NVD returned no vulnerabilities for the selected period."
    )

    original_cve = vulnerabilities[0].get("cve")

    assert isinstance(original_cve, dict)

    source = NVDThreatSource()

    cve = deepcopy(original_cve)
    cve.pop("metrics", None)

    threat = source._parse_cve(cve)

    assert threat.severity is None
    assert threat.cvss_score is None

    cve = deepcopy(original_cve)
    cve.pop("references", None)

    threat = source._parse_cve(cve)

    assert threat.references == []

    cve = deepcopy(original_cve)
    cve.pop("weaknesses", None)

    threat = source._parse_cve(cve)

    assert threat.weaknesses == []

    cve = deepcopy(original_cve)
    cve.pop("affected", None)

    threat = source._parse_cve(cve)

    assert threat.affected_products == []