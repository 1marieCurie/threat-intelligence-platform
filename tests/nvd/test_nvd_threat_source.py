
from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from application.services.nvd_threat_source import (
    NVDThreatSource,
)
from domain.threat import Threat
from domain.threat_category import ThreatCategory
from domain.weakness_reference import WeaknessReference
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

        # Real NVD 2.0 affected-product structure:
        #
        # configurations[]
        #   └── nodes[]
        #         └── cpeMatch[]
        "configurations": [
            {
                "operator": "OR",
                "negate": False,
                "nodes": [
                    {
                        "operator": "OR",
                        "negate": False,
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": (
                                    "cpe:2.3:a:example_vendor:"
                                    "example_product:*:*:*:*:*:"
                                    "windows:*:*"
                                ),
                                "versionStartIncluding": "1.0.0",
                                "versionEndExcluding": "2.0.0",
                                "matchCriteriaId": (
                                    "11111111-2222-3333-4444-"
                                    "555555555555"
                                ),
                            }
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
# Basic service tests
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

    # Identity and source
    assert threat.id == "CVE-2026-12345"
    assert threat.source == "NVD"
    assert threat.category is ThreatCategory.VULNERABILITY

    # Description
    assert threat.description == (
        "A remote code execution vulnerability affects "
        "Example Product before version 2.0.0."
    )

    # CVSS
    assert threat.severity == "CRITICAL"
    assert threat.cvss_score == 9.8

    # CWE references
    assert isinstance(
        threat.weakness_references,
        list,
    )

    assert len(threat.weakness_references) == 1

    weakness_reference = (
        threat.weakness_references[0]
    )

    assert isinstance(
        weakness_reference,
        WeaknessReference,
    )

    assert weakness_reference.source == "NVD"
    assert weakness_reference.cwe_id == "CWE-78"

    assert (
        weakness_reference.source_description
        == "CWE-78"
    )

    assert weakness_reference.source_type == "Primary"
    assert weakness_reference.language == "en"
    assert weakness_reference.origin == "nvd_primary"

    assert (
        weakness_reference.resolution_status
        == "resolved"
    )

    assert (
        weakness_reference.resolution_method
        == "explicit_id"
    )

    assert weakness_reference.raw == {
        "weakness_source": "nvd@nist.gov",
        "weakness_type": "Primary",
        "description": {
            "lang": "en",
            "value": "CWE-78",
        },
    }

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

    # Affected products extracted from CPE
    assert len(threat.affected_products) == 1

    assert threat.affected_products[0] == {
        "vendor": "example_vendor",
        "product": "example_product",
        "part": "a",
        "platforms": [
            "windows",
        ],
        "versions": [
            {
                "versionStartIncluding": "1.0.0",
                "versionEndExcluding": "2.0.0",
            }
        ],
        "vulnerable": True,
        "criteria": (
            "cpe:2.3:a:example_vendor:"
            "example_product:*:*:*:*:*:"
            "windows:*:*"
        ),
        "match_criteria_id": (
            "11111111-2222-3333-4444-"
            "555555555555"
        ),
    }

    # Raw source preservation
    assert threat.raw == sample_cve


# ============================================================
# Description tests
# ============================================================


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


def test_invalid_descriptions_type(
    sample_cve: dict[str, Any],
) -> None:
    source = NVDThreatSource()

    cve = deepcopy(sample_cve)
    cve["descriptions"] = None

    threat = source._parse_cve(cve)

    assert threat.description == ""


def test_description_ignores_invalid_elements(
    sample_cve: dict[str, Any],
) -> None:
    source = NVDThreatSource()

    cve = deepcopy(sample_cve)

    cve["descriptions"] = [
        None,
        "invalid",
        {
            "lang": "en",
            "value": "Valid description.",
        },
    ]

    threat = source._parse_cve(cve)

    assert threat.description == "Valid description."


# ============================================================
# Missing field tests
# ============================================================


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
    print(threat.weakness_references)

    assert threat.weakness_references == []


def test_missing_affected_products(
    sample_cve: dict[str, Any],
) -> None:
    """
    Missing configurations and legacy affected data must produce
    an empty list.
    """

    source = NVDThreatSource()

    cve = deepcopy(sample_cve)
    cve.pop("configurations", None)
    cve.pop("affected", None)

    threat = source._parse_cve(cve)

    print("\n========== NO AFFECTED PRODUCTS ==========")
    print(threat.affected_products)

    assert threat.affected_products == []


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


def test_empty_cve_identifier_raises_value_error(
    sample_cve: dict[str, Any],
) -> None:
    source = NVDThreatSource()

    cve = deepcopy(sample_cve)
    cve["id"] = "   "

    with pytest.raises(
        ValueError,
        match="Missing CVE identifier",
    ):
        source._parse_cve(cve)


def test_non_string_cve_identifier_raises_value_error(
    sample_cve: dict[str, Any],
) -> None:
    source = NVDThreatSource()

    cve = deepcopy(sample_cve)
    cve["id"] = 12345

    with pytest.raises(
        ValueError,
        match="Missing CVE identifier",
    ):
        source._parse_cve(cve)


# ============================================================
# Parse tests
# ============================================================


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
    assert threat.source == "NVD"
    assert threat.cvss_score == 9.8
    assert len(threat.affected_products) == 1
    assert len(threat.weakness_references) == 1


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


def test_parse_invalid_raw_data() -> None:
    source = NVDThreatSource()

    assert source.parse(None) == []
    assert source.parse([]) == []
    assert source.parse("invalid") == []


def test_parse_invalid_vulnerabilities_type() -> None:
    source = NVDThreatSource()

    assert source.parse(
        {
            "vulnerabilities": None,
        }
    ) == []

    assert source.parse(
        {
            "vulnerabilities": {},
        }
    ) == []


def test_parse_ignores_invalid_vulnerability_elements(
    sample_cve: dict[str, Any],
) -> None:
    """
    None, strings and malformed objects must be ignored without
    preventing valid CVEs from being parsed.
    """

    source = NVDThreatSource()

    raw = {
        "vulnerabilities": [
            None,
            "invalid",
            123,
            {},
            {
                "cve": None,
            },
            {
                "cve": "invalid",
            },
            {
                "cve": deepcopy(sample_cve),
            },
        ]
    }

    threats = source.parse(raw)

    assert len(threats) == 1
    assert threats[0].id == "CVE-2026-12345"


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


def test_cvss_skips_invalid_first_metric(
    sample_cve: dict[str, Any],
) -> None:
    source = NVDThreatSource()

    cve = deepcopy(sample_cve)

    cve["metrics"] = {
        "cvssMetricV31": [
            None,
            {
                "cvssData": {
                    "version": "3.1",
                    "baseScore": 8.1,
                    "baseSeverity": "HIGH",
                }
            },
        ]
    }

    assert source._extract_cvss(cve) == 8.1
    assert source._extract_severity(cve) == "HIGH"


def test_cvss_boolean_score_is_rejected(
    sample_cve: dict[str, Any],
) -> None:
    source = NVDThreatSource()

    cve = deepcopy(sample_cve)

    cve["metrics"] = {
        "cvssMetricV31": [
            {
                "cvssData": {
                    "version": "3.1",
                    "baseScore": True,
                    "baseSeverity": "HIGH",
                }
            }
        ]
    }

    assert source._extract_cvss(cve) is None
    assert source._extract_severity(cve) == "HIGH"


def test_invalid_metrics_type_returns_none(
    sample_cve: dict[str, Any],
) -> None:
    source = NVDThreatSource()

    cve = deepcopy(sample_cve)
    cve["metrics"] = None

    assert source._extract_cvss(cve) is None
    assert source._extract_severity(cve) is None


# ============================================================
# WeaknessReference unit tests
# ============================================================


def test_extract_resolved_weakness_reference(
    sample_cve: dict[str, Any],
) -> None:
    source = NVDThreatSource()

    references = (
        source._extract_weakness_references(
            deepcopy(sample_cve)
        )
    )

    assert len(references) == 1

    reference = references[0]

    assert isinstance(reference, WeaknessReference)
    assert reference.source == "NVD"
    assert reference.cwe_id == "CWE-78"
    assert reference.origin == "nvd_primary"

    assert (
        reference.resolution_status
        == "resolved"
    )

    assert (
        reference.resolution_method
        == "explicit_id"
    )


@pytest.mark.parametrize(
    "placeholder",
    [
        "NVD-CWE-noinfo",
        "NVD-CWE-Other",
        "CWE-noinfo",
        "CWE-Other",
    ],
)
def test_extract_cwe_placeholder(
    sample_cve: dict[str, Any],
    placeholder: str,
) -> None:
    source = NVDThreatSource()

    cve = deepcopy(sample_cve)

    cve["weaknesses"][0]["description"][0][
        "value"
    ] = placeholder

    references = (
        source._extract_weakness_references(cve)
    )

    assert len(references) == 1

    reference = references[0]

    assert reference.cwe_id is None

    assert (
        reference.source_description
        == placeholder
    )

    assert (
        reference.resolution_status
        == "placeholder"
    )

    assert (
        reference.resolution_method
        == "source_placeholder"
    )


def test_extract_cwe_id_from_combined_text(
    sample_cve: dict[str, Any],
) -> None:
    source = NVDThreatSource()

    cve = deepcopy(sample_cve)

    cve["weaknesses"][0]["description"][0][
        "value"
    ] = "CWE-79: Improper Neutralization of Input"

    references = (
        source._extract_weakness_references(cve)
    )

    assert len(references) == 1

    reference = references[0]

    assert reference.cwe_id == "CWE-79"

    assert (
        reference.resolution_status
        == "resolved"
    )

    assert (
        reference.resolution_method
        == "extracted_id"
    )


def test_extract_invalid_cwe_identifier(
    sample_cve: dict[str, Any],
) -> None:
    source = NVDThreatSource()

    cve = deepcopy(sample_cve)

    cve["weaknesses"][0]["description"][0][
        "value"
    ] = "CWE-ABC"

    references = (
        source._extract_weakness_references(cve)
    )

    assert len(references) == 1

    reference = references[0]

    assert reference.cwe_id is None

    assert (
        reference.resolution_status
        == "invalid"
    )

    assert reference.resolution_method is None


def test_extract_unresolved_weakness_description(
    sample_cve: dict[str, Any],
) -> None:
    source = NVDThreatSource()

    cve = deepcopy(sample_cve)

    cve["weaknesses"][0]["description"][0][
        "value"
    ] = "Improper input validation"

    references = (
        source._extract_weakness_references(cve)
    )

    assert len(references) == 1

    reference = references[0]

    assert reference.cwe_id is None

    assert (
        reference.resolution_status
        == "unresolved"
    )

    assert reference.resolution_method is None


def test_extract_secondary_weakness_origin(
    sample_cve: dict[str, Any],
) -> None:
    source = NVDThreatSource()

    cve = deepcopy(sample_cve)
    cve["weaknesses"][0]["type"] = "Secondary"

    references = (
        source._extract_weakness_references(cve)
    )

    assert references[0].origin == "nvd_secondary"


def test_extract_weakness_references_removes_duplicates(
    sample_cve: dict[str, Any],
) -> None:
    source = NVDThreatSource()

    cve = deepcopy(sample_cve)

    duplicate = deepcopy(
        cve["weaknesses"][0]["description"][0]
    )

    cve["weaknesses"][0]["description"].append(
        duplicate
    )

    references = (
        source._extract_weakness_references(cve)
    )

    assert len(references) == 1
    assert references[0].cwe_id == "CWE-78"


def test_extract_weakness_references_ignores_invalid_elements(
    sample_cve: dict[str, Any],
) -> None:
    source = NVDThreatSource()

    cve = deepcopy(sample_cve)

    cve["weaknesses"] = [
        None,
        "invalid",
        {
            "source": "nvd@nist.gov",
            "type": "Primary",
            "description": [
                None,
                "invalid",
                {
                    "lang": "en",
                    "value": "CWE-89",
                },
            ],
        },
    ]

    references = (
        source._extract_weakness_references(cve)
    )

    assert len(references) == 1
    assert references[0].cwe_id == "CWE-89"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("CWE-79", "CWE-79"),
        ("cwe-79", "CWE-79"),
        ("79", "CWE-79"),
        (79, "CWE-79"),
        ("CWE-00079", "CWE-79"),
        ("0", None),
        (0, None),
        (-1, None),
        (True, None),
        ("CWE-ABC", None),
        ("", None),
        (None, None),
    ],
)
def test_normalize_cwe_id(
    value: Any,
    expected: str | None,
) -> None:
    assert (
        NVDThreatSource._normalize_cwe_id(value)
        == expected
    )


# ============================================================
# Affected-product and CPE tests
# ============================================================


def test_extract_product_from_cpe_configuration(
    sample_cve: dict[str, Any],
) -> None:
    source = NVDThreatSource()

    products = source._extract_affected_products(
        deepcopy(sample_cve)
    )

    assert len(products) == 1

    product = products[0]

    assert product["vendor"] == "example_vendor"
    assert product["product"] == "example_product"
    assert product["part"] == "a"

    assert product["platforms"] == [
        "windows",
    ]

    assert product["versions"] == [
        {
            "versionStartIncluding": "1.0.0",
            "versionEndExcluding": "2.0.0",
        }
    ]

    assert product["vulnerable"] is True


def test_extract_exact_cpe_version(
    sample_cve: dict[str, Any],
) -> None:
    source = NVDThreatSource()

    cve = deepcopy(sample_cve)

    cpe_match = (
        cve["configurations"][0]
        ["nodes"][0]
        ["cpeMatch"][0]
    )

    cpe_match["criteria"] = (
        "cpe:2.3:a:example_vendor:"
        "example_product:1.5.0:*:*:*:*:"
        "linux:*:*"
    )

    cpe_match.pop(
        "versionStartIncluding",
        None,
    )

    cpe_match.pop(
        "versionEndExcluding",
        None,
    )

    products = source._extract_affected_products(
        cve
    )

    assert products[0]["versions"] == [
        {
            "version": "1.5.0",
        }
    ]

    assert products[0]["platforms"] == [
        "linux",
    ]


def test_extract_product_from_child_node(
    sample_cve: dict[str, Any],
) -> None:
    """
    Nested child nodes must be traversed recursively.
    """

    source = NVDThreatSource()

    cve = deepcopy(sample_cve)

    cpe_match = deepcopy(
        cve["configurations"][0]
        ["nodes"][0]
        ["cpeMatch"][0]
    )

    cve["configurations"][0]["nodes"] = [
        {
            "operator": "OR",
            "children": [
                {
                    "operator": "OR",
                    "cpeMatch": [
                        cpe_match,
                    ],
                }
            ],
        }
    ]

    products = source._extract_affected_products(
        cve
    )

    assert len(products) == 1

    assert (
        products[0]["product"]
        == "example_product"
    )


def test_affected_products_remove_duplicates(
    sample_cve: dict[str, Any],
) -> None:
    source = NVDThreatSource()

    cve = deepcopy(sample_cve)

    cpe_match = deepcopy(
        cve["configurations"][0]
        ["nodes"][0]
        ["cpeMatch"][0]
    )

    cve["configurations"][0][
        "nodes"
    ][0]["cpeMatch"].append(cpe_match)

    products = source._extract_affected_products(
        cve
    )

    assert len(products) == 1


def test_invalid_cpe_match_is_ignored(
    sample_cve: dict[str, Any],
) -> None:
    source = NVDThreatSource()

    cve = deepcopy(sample_cve)

    cve["configurations"][0][
        "nodes"
    ][0]["cpeMatch"] = [
        None,
        "invalid",
        {},
        {
            "criteria": None,
        },
    ]

    products = source._extract_affected_products(
        cve
    )

    assert products == []


def test_invalid_configurations_are_ignored(
    sample_cve: dict[str, Any],
) -> None:
    source = NVDThreatSource()

    cve = deepcopy(sample_cve)

    cve["configurations"] = [
        None,
        "invalid",
        {
            "nodes": None,
        },
    ]

    products = source._extract_affected_products(
        cve
    )

    assert products == []


def test_legacy_affected_products_are_supported(
    sample_cve: dict[str, Any],
) -> None:
    """
    Older fixtures using affected/affectedData must remain
    compatible.
    """

    source = NVDThreatSource()

    cve = deepcopy(sample_cve)
    cve.pop("configurations", None)

    cve["affected"] = [
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
                        }
                    ],
                }
            ],
        }
    ]

    products = source._extract_affected_products(
        cve
    )

    assert products == [
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
                }
            ],
        }
    ]


def test_legacy_vendor_na_becomes_none(
    sample_cve: dict[str, Any],
) -> None:
    source = NVDThreatSource()

    cve = deepcopy(sample_cve)
    cve.pop("configurations", None)

    cve["affected"] = [
        {
            "affectedData": [
                {
                    "vendor": "n/a",
                    "product": "Example Product",
                    "platforms": [],
                    "versions": [],
                }
            ]
        }
    ]

    threat = source._parse_cve(cve)

    assert (
        threat.affected_products[0]["vendor"]
        is None
    )


def test_legacy_product_na_becomes_none(
    sample_cve: dict[str, Any],
) -> None:
    source = NVDThreatSource()

    cve = deepcopy(sample_cve)
    cve.pop("configurations", None)

    cve["affected"] = [
        {
            "affectedData": [
                {
                    "vendor": "Example Vendor",
                    "product": "n/a",
                    "platforms": [],
                    "versions": [],
                }
            ]
        }
    ]

    threat = source._parse_cve(cve)

    assert (
        threat.affected_products[0]["product"]
        is None
    )


# ============================================================
# Reference tests
# ============================================================


def test_references_remove_duplicates(
    sample_cve: dict[str, Any],
) -> None:
    source = NVDThreatSource()

    cve = deepcopy(sample_cve)

    duplicate = deepcopy(
        cve["references"][0]
    )

    cve["references"].append(duplicate)

    references = source._extract_references(cve)

    assert references == [
        (
            "https://example.org/advisory/"
            "CVE-2026-12345"
        ),
        (
            "https://example.org/patch/"
            "CVE-2026-12345"
        ),
    ]


def test_references_ignore_invalid_elements(
    sample_cve: dict[str, Any],
) -> None:
    source = NVDThreatSource()

    cve = deepcopy(sample_cve)

    cve["references"] = [
        None,
        "invalid",
        {},
        {
            "url": None,
        },
        {
            "url": "   ",
        },
        {
            "url": "https://example.org/valid",
        },
    ]

    references = source._extract_references(cve)

    assert references == [
        "https://example.org/valid",
    ]


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
        cwe_ids = [
            reference.cwe_id
            for reference
            in threat.weakness_references
            if reference.cwe_id is not None
        ]

        print("--------------------------------")
        print(f"ID          : {threat.id}")
        print(f"Severity    : {threat.severity}")
        print(f"CVSS Score  : {threat.cvss_score}")
        print(f"CWEs        : {cwe_ids}")
        print(
            "Products    :",
            len(threat.affected_products),
        )

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
        assert threat.source == "NVD"

        assert isinstance(
            threat.weakness_references,
            list,
        )

        assert isinstance(
            threat.affected_products,
            list,
        )


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
        assert threat.source == "NVD"


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
        assert threat.source == "NVD"


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

    original_cve = vulnerabilities[0].get(
        "cve"
    )

    assert isinstance(original_cve, dict)

    source = NVDThreatSource()

    # Missing metrics
    cve = deepcopy(original_cve)
    cve.pop("metrics", None)

    threat = source._parse_cve(cve)

    assert threat.severity is None
    assert threat.cvss_score is None

    # Missing references
    cve = deepcopy(original_cve)
    cve.pop("references", None)

    threat = source._parse_cve(cve)

    assert threat.references == []

    # Missing weaknesses
    cve = deepcopy(original_cve)
    cve.pop("weaknesses", None)

    threat = source._parse_cve(cve)

    assert threat.weakness_references == []

    # Missing affected-product structures
    cve = deepcopy(original_cve)
    cve.pop("configurations", None)
    cve.pop("affected", None)

    threat = source._parse_cve(cve)

    assert threat.affected_products == []

