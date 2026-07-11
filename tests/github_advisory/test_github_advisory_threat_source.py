from __future__ import annotations

from typing import Any

import pytest

from application.services.github_advisory_threat_source import (
    GitHubAdvisoryThreatSource,
)
from domain.collection_result import CollectionResult
from domain.threat import Threat
from infrastructure.adapters.outbound.github_advisory_connector import (
    GitHubAdvisoryConnector,
)


# ============================================================
# Fake connector
# ============================================================


class FakeGitHubAdvisoryConnector(GitHubAdvisoryConnector):
    """
    Fake outbound connector used to test the application service
    without calling the real GitHub API.
    """

    def __init__(
        self,
        advisories: list[dict[str, Any]] | None = None,
    ) -> None:
        super().__init__()

        self.advisories = advisories or []
        self.calls: list[dict[str, Any]] = []

    def fetch_advisories(
        self,
        *,
        ghsa_id: str | None = None,
        advisory_type: str = "reviewed",
        cve_id: str | None = None,
        ecosystem: str | None = None,
        severity: str | None = None,
        cwes: list[str | int] | None = None,
        is_withdrawn: bool | None = None,
        affects: list[str] | None = None,
        published: str | None = None,
        updated: str | None = None,
        modified: str | None = None,
        epss_percentage: str | None = None,
        epss_percentile: str | None = None,
        direction: str = "desc",
        sort: str = "published",
        per_page: int = 30,
        before: str | None = None,
        after: str | None = None,
        max_pages: int | None = 1,
    ) -> list[dict[str, Any]]:
        self.calls.append(
            {
                "ghsa_id": ghsa_id,
                "advisory_type": advisory_type,
                "cve_id": cve_id,
                "ecosystem": ecosystem,
                "severity": severity,
                "cwes": cwes,
                "is_withdrawn": is_withdrawn,
                "affects": affects,
                "published": published,
                "updated": updated,
                "modified": modified,
                "epss_percentage": epss_percentage,
                "epss_percentile": epss_percentile,
                "direction": direction,
                "sort": sort,
                "per_page": per_page,
                "before": before,
                "after": after,
                "max_pages": max_pages,
            }
        )

        return self.advisories


# ============================================================
# Fixtures
# ============================================================


@pytest.fixture
def complete_advisory() -> dict[str, Any]:
    return {
        "ghsa_id": "GHSA-jfh8-c2jp-5v3q",
        "cve_id": "CVE-2021-44228",
        "identifiers": [
            {
                "type": "GHSA",
                "value": "GHSA-jfh8-c2jp-5v3q",
            },
            {
                "type": "CVE",
                "value": "CVE-2021-44228",
            },
            {
                "type": "CVE",
                "value": "CVE-2021-44228",
            },
        ],
        "type": "reviewed",
        "severity": "critical",
        "summary": "Log4Shell vulnerability",
        "description": (
            "Remote code execution vulnerability in Apache Log4j."
        ),
        "published_at": "2021-12-10T00:00:00Z",
        "updated_at": "2023-01-01T00:00:00Z",
        "github_reviewed_at": "2021-12-10T12:00:00Z",
        "withdrawn_at": None,
        "nvd_published_at": "2021-12-10T10:15:00Z",
        "vulnerabilities": [
            {
                "package": {
                    "ecosystem": "maven",
                    "name": (
                        "org.apache.logging.log4j:"
                        "log4j-core"
                    ),
                },
                "vulnerable_version_range": (
                    ">= 2.0-beta9, < 2.15.0"
                ),
                "first_patched_version": {
                    "identifier": "2.15.0",
                },
                "vulnerable_functions": [
                    (
                        "org.apache.logging.log4j.core."
                        "lookup.JndiLookup.lookup"
                    ),
                    (
                        "org.apache.logging.log4j.core."
                        "lookup.JndiLookup.lookup"
                    ),
                ],
                "source_code_location": {
                    "url": (
                        "https://github.com/apache/"
                        "logging-log4j2"
                    ),
                    "path": (
                        "log4j-core/src/main/java/"
                        "JndiLookup.java"
                    ),
                },
            }
        ],
        "cvss_severities": {
            "cvss_v3": {
                "score": 10.0,
                "vector_string": (
                    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/"
                    "S:C/C:H/I:H/A:H"
                ),
            },
            "cvss_v4": {
                "score": 9.3,
                "vector_string": (
                    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/"
                    "UI:N/VC:H/VI:H/VA:H"
                ),
            },
        },
        "epss": {
            "percentage": 0.94321,
            "percentile": 0.9999,
        },
        "cwes": [
            {
                "cwe_id": "CWE-502",
                "name": "Deserialization of Untrusted Data",
            },
            {
                "cwe_id": "cwe-20",
                "name": "Improper Input Validation",
            },
            {
                "cwe_id": "CWE-502",
                "name": "Deserialization of Untrusted Data",
            },
        ],
        "references": [
            "https://logging.apache.org/log4j/",
            {
                "url": (
                    "https://nvd.nist.gov/vuln/detail/"
                    "CVE-2021-44228"
                )
            },
            "https://logging.apache.org/log4j/",
        ],
        "url": (
            "https://api.github.com/advisories/"
            "GHSA-jfh8-c2jp-5v3q"
        ),
        "html_url": (
            "https://github.com/advisories/"
            "GHSA-jfh8-c2jp-5v3q"
        ),
        "repository_advisory_url": (
            "https://api.github.com/repos/apache/"
            "logging-log4j2/security-advisories/"
            "GHSA-jfh8-c2jp-5v3q"
        ),
        "source_code_location": [
            "https://github.com/apache/logging-log4j2",
            "https://github.com/apache/logging-log4j2",
        ],
    }


@pytest.fixture
def ghsa_only_advisory() -> dict[str, Any]:
    return {
        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        "cve_id": None,
        "identifiers": [
            {
                "type": "GHSA",
                "value": "GHSA-aaaa-bbbb-cccc",
            }
        ],
        "type": "unreviewed",
        "severity": "medium",
        "summary": "Advisory without CVE",
        "description": "GitHub advisory without a CVE identifier.",
        "vulnerabilities": [],
        "cwes": [],
        "references": [],
    }


# ============================================================
# Basic service tests
# ============================================================


def test_unit_source_name() -> None:
    source = GitHubAdvisoryThreatSource(
        connector=FakeGitHubAdvisoryConnector()
    )

    assert source.name() == "github_advisory"


def test_unit_fetch_raw_calls_connector_with_configuration(
    complete_advisory: dict[str, Any],
) -> None:
    connector = FakeGitHubAdvisoryConnector(
        advisories=[complete_advisory]
    )

    source = GitHubAdvisoryThreatSource(
        connector=connector,
        advisory_type="reviewed",
        ecosystem="maven",
        severity="critical",
        modified="2026-07-01..2026-07-10",
        per_page=50,
        max_pages=2,
    )

    result = source.fetch_raw()

    assert result == [complete_advisory]
    assert len(connector.calls) == 1

    call = connector.calls[0]

    assert call["advisory_type"] == "reviewed"
    assert call["ecosystem"] == "maven"
    assert call["severity"] == "critical"
    assert call["modified"] == "2026-07-01..2026-07-10"
    assert call["per_page"] == 50
    assert call["max_pages"] == 2


# ============================================================
# Complete mapping test
# ============================================================


def test_unit_maps_complete_advisory_to_threat(
    complete_advisory: dict[str, Any],
) -> None:
    source = GitHubAdvisoryThreatSource(
        connector=FakeGitHubAdvisoryConnector()
    )

    threats = source.parse([complete_advisory])

    assert len(threats) == 1

    threat = threats[0]

    assert isinstance(threat, Threat)

    # Identity
    assert threat.id == "CVE-2021-44228"

    assert threat.external_ids == {
        "GHSA": ["GHSA-jfh8-c2jp-5v3q"],
        "CVE": ["CVE-2021-44228"],
    }

    # Core information
    assert threat.title == "Log4Shell vulnerability"
    assert threat.description == (
        "Remote code execution vulnerability in Apache Log4j."
    )
    assert threat.advisory_type == "reviewed"
    assert threat.severity == "CRITICAL"

    # CVSS
    assert threat.cvss_score == 9.3

    assert threat.cvss_metrics == {
        "3.1": {
            "score": 10.0,
            "vector": (
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/"
                "S:C/C:H/I:H/A:H"
            ),
        },
        "4.0": {
            "score": 9.3,
            "vector": (
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/"
                "UI:N/VC:H/VI:H/VA:H"
            ),
        },
    }

    # EPSS
    assert threat.epss_score == pytest.approx(
        0.94321
    )
    assert threat.epss_percentile == pytest.approx(
        0.9999
    )
    assert threat.epss_date is None

    # Affected package
    assert len(threat.affected_products) == 1

    affected = threat.affected_products[0]

    assert affected["ecosystem"] == "maven"
    assert affected["package_name"] == (
        "org.apache.logging.log4j:log4j-core"
    )
    assert affected["vulnerable_version_range"] == (
        ">= 2.0-beta9, < 2.15.0"
    )
    assert affected["first_patched_version"] == "2.15.0"
    assert affected["vulnerable_functions"] == [
        (
            "org.apache.logging.log4j.core."
            "lookup.JndiLookup.lookup"
        )
    ]

    # CWE
    assert threat.weaknesses == [
        "CWE-502",
        "CWE-20",
    ]

    assert threat.weakness_details == [
        {
            "cwe_id": "CWE-502",
            "name": "Deserialization of Untrusted Data",
            "source": "github_advisory",
            "is_official": False,
        },
        {
            "cwe_id": "CWE-20",
            "name": "Improper Input Validation",
            "source": "github_advisory",
            "is_official": False,
        },
    ]

    # Labels
    assert threat.labels == [
        "github:reviewed",
        "ecosystem:maven",
    ]

    # References
    assert threat.references == [
        "https://logging.apache.org/log4j/",
        (
            "https://nvd.nist.gov/vuln/detail/"
            "CVE-2021-44228"
        ),
    ]

    # Source URLs
    assert threat.source_urls == {
        "api": (
            "https://api.github.com/advisories/"
            "GHSA-jfh8-c2jp-5v3q"
        ),
        "html": (
            "https://github.com/advisories/"
            "GHSA-jfh8-c2jp-5v3q"
        ),
        "repository_advisory": (
            "https://api.github.com/repos/apache/"
            "logging-log4j2/security-advisories/"
            "GHSA-jfh8-c2jp-5v3q"
        ),
    }

    # Source code locations
    assert threat.source_code_locations == [
        "https://github.com/apache/logging-log4j2",
        (
            "log4j-core/src/main/java/"
            "JndiLookup.java"
        ),
    ]

    # Dates
    assert threat.published_date == (
        "2021-12-10T00:00:00Z"
    )
    assert threat.last_modified_date == (
        "2023-01-01T00:00:00Z"
    )
    assert threat.reviewed_date == (
        "2021-12-10T12:00:00Z"
    )
    assert threat.withdrawn_date is None

    assert threat.source_dates == {
        "github_published_at": (
            "2021-12-10T00:00:00Z"
        ),
        "github_updated_at": (
            "2023-01-01T00:00:00Z"
        ),
        "github_reviewed_at": (
            "2021-12-10T12:00:00Z"
        ),
        "nvd_published_at": (
            "2021-12-10T10:15:00Z"
        ),
    }

    # Raw data
    assert threat.raw == {
        "github_advisory": complete_advisory
    }


# ============================================================
# Canonical identifier tests
# ============================================================


def test_unit_prefers_cve_as_canonical_id(
    complete_advisory: dict[str, Any],
) -> None:
    source = GitHubAdvisoryThreatSource(
        connector=FakeGitHubAdvisoryConnector()
    )

    threat = source.parse(
        [complete_advisory]
    )[0]

    assert threat.id == "CVE-2021-44228"


def test_unit_uses_ghsa_when_cve_is_absent(
    ghsa_only_advisory: dict[str, Any],
) -> None:
    source = GitHubAdvisoryThreatSource(
        connector=FakeGitHubAdvisoryConnector()
    )

    threats = source.parse(
        [ghsa_only_advisory]
    )

    assert len(threats) == 1
    assert threats[0].id == "GHSA-aaaa-bbbb-cccc"

    assert threats[0].external_ids == {
        "GHSA": ["GHSA-aaaa-bbbb-cccc"]
    }


def test_unit_uses_cve_from_identifiers_when_direct_cve_is_absent() -> None:
    advisory = {
        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        "cve_id": None,
        "identifiers": [
            {
                "type": "CVE",
                "value": "CVE-2026-12345",
            },
            {
                "type": "GHSA",
                "value": "GHSA-aaaa-bbbb-cccc",
            },
        ],
    }

    source = GitHubAdvisoryThreatSource(
        connector=FakeGitHubAdvisoryConnector()
    )

    threats = source.parse([advisory])

    assert len(threats) == 1
    assert threats[0].id == "CVE-2026-12345"


def test_unit_skips_advisory_without_usable_identifier() -> None:
    advisory = {
        "ghsa_id": None,
        "cve_id": None,
        "identifiers": [],
        "summary": "Invalid advisory",
    }

    source = GitHubAdvisoryThreatSource(
        connector=FakeGitHubAdvisoryConnector()
    )

    assert source.parse([advisory]) == []


# ============================================================
# External identifier tests
# ============================================================


def test_unit_external_ids_are_normalized_and_deduplicated() -> None:
    advisory = {
        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        "cve_id": "CVE-2026-12345",
        "identifiers": [
            {
                "type": "cve",
                "value": "CVE-2026-12345",
            },
            {
                "type": "CVE",
                "value": "CVE-2026-12345",
            },
            {
                "type": "ghsa",
                "value": "GHSA-aaaa-bbbb-cccc",
            },
            {
                "type": "OTHER",
                "value": "OTHER-123",
            },
        ],
    }

    source = GitHubAdvisoryThreatSource(
        connector=FakeGitHubAdvisoryConnector()
    )

    threat = source.parse([advisory])[0]

    assert threat.external_ids == {
        "CVE": ["CVE-2026-12345"],
        "GHSA": ["GHSA-aaaa-bbbb-cccc"],
        "OTHER": ["OTHER-123"],
    }


# ============================================================
# CVSS tests
# ============================================================


def test_unit_prefers_cvss_v4_score_over_v3() -> None:
    advisory = {
        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        "cvss_severities": {
            "cvss_v3": {
                "score": 9.8,
                "vector_string": "CVSS:3.1/AV:N",
            },
            "cvss_v4": {
                "score": 8.7,
                "vector_string": "CVSS:4.0/AV:N",
            },
        },
    }

    source = GitHubAdvisoryThreatSource(
        connector=FakeGitHubAdvisoryConnector()
    )

    threat = source.parse([advisory])[0]

    assert threat.cvss_score == 8.7
    assert set(threat.cvss_metrics) == {
        "3.1",
        "4.0",
    }


def test_unit_uses_cvss_v3_when_v4_is_missing() -> None:
    advisory = {
        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        "cvss_severities": {
            "cvss_v3": {
                "score": "9.8",
                "vector_string": "CVSS:3.1/AV:N",
            },
            "cvss_v4": None,
        },
    }

    source = GitHubAdvisoryThreatSource(
        connector=FakeGitHubAdvisoryConnector()
    )

    threat = source.parse([advisory])[0]

    assert threat.cvss_score == 9.8
    assert threat.cvss_metrics["3.1"]["score"] == 9.8


def test_unit_supports_legacy_cvss_object() -> None:
    advisory = {
        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        "cvss": {
            "score": 7.5,
            "vector_string": "CVSS:3.1/AV:N",
        },
    }

    source = GitHubAdvisoryThreatSource(
        connector=FakeGitHubAdvisoryConnector()
    )

    threat = source.parse([advisory])[0]

    assert threat.cvss_score == 7.5

    assert threat.cvss_metrics == {
        "3.1": {
            "score": 7.5,
            "vector": "CVSS:3.1/AV:N",
        }
    }


def test_unit_invalid_cvss_score_becomes_none() -> None:
    advisory = {
        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        "cvss_severities": {
            "cvss_v3": {
                "score": "invalid",
                "vector_string": None,
            }
        },
    }

    source = GitHubAdvisoryThreatSource(
        connector=FakeGitHubAdvisoryConnector()
    )

    threat = source.parse([advisory])[0]

    assert threat.cvss_score is None
    assert threat.cvss_metrics == {}


# ============================================================
# EPSS tests
# ============================================================


def test_unit_maps_epss_string_values_to_float() -> None:
    advisory = {
        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        "epss": {
            "percentage": "0.75",
            "percentile": "0.98",
        },
    }

    source = GitHubAdvisoryThreatSource(
        connector=FakeGitHubAdvisoryConnector()
    )

    threat = source.parse([advisory])[0]

    assert threat.epss_score == 0.75
    assert threat.epss_percentile == 0.98


def test_unit_missing_epss_returns_none_values() -> None:
    advisory = {
        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
    }

    source = GitHubAdvisoryThreatSource(
        connector=FakeGitHubAdvisoryConnector()
    )

    threat = source.parse([advisory])[0]

    assert threat.epss_score is None
    assert threat.epss_percentile is None


# ============================================================
# Affected product tests
# ============================================================


def test_unit_maps_multiple_affected_packages() -> None:
    advisory = {
        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        "vulnerabilities": [
            {
                "package": {
                    "ecosystem": "pip",
                    "name": "example-package",
                },
                "vulnerable_version_range": "< 2.0.0",
                "first_patched_version": {
                    "identifier": "2.0.0"
                },
                "vulnerable_functions": [
                    "example.run"
                ],
            },
            {
                "package": {
                    "ecosystem": "npm",
                    "name": "example-js-package",
                },
                "vulnerable_version_range": "<= 1.5.0",
                "first_patched_version": None,
                "vulnerable_functions": [],
            },
        ],
    }

    source = GitHubAdvisoryThreatSource(
        connector=FakeGitHubAdvisoryConnector()
    )

    threat = source.parse([advisory])[0]

    assert len(threat.affected_products) == 2

    assert threat.affected_products[0] == {
        "ecosystem": "pip",
        "package_name": "example-package",
        "vulnerable_version_range": "< 2.0.0",
        "first_patched_version": "2.0.0",
        "vulnerable_functions": [
            "example.run"
        ],
    }

    assert threat.affected_products[1] == {
        "ecosystem": "npm",
        "package_name": "example-js-package",
        "vulnerable_version_range": "<= 1.5.0",
        "vulnerable_functions": [],
    }


def test_unit_ignores_invalid_vulnerability_elements() -> None:
    advisory = {
        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        "vulnerabilities": [
            None,
            "invalid",
            123,
        ],
    }

    source = GitHubAdvisoryThreatSource(
        connector=FakeGitHubAdvisoryConnector()
    )

    threat = source.parse([advisory])[0]

    assert threat.affected_products == []


# ============================================================
# CWE tests
# ============================================================


@pytest.mark.parametrize(
    ("raw_cwe", "expected"),
    [
        (79, "CWE-79"),
        ("79", "CWE-79"),
        ("CWE-79", "CWE-79"),
        ("cwe-79", "CWE-79"),
        (" CWE-502 ", "CWE-502"),
        ("invalid", None),
        ("CWE-ABC", None),
        (-1, None),
        (None, None),
    ],
)
def test_unit_normalize_cwe_id(
    raw_cwe: Any,
    expected: str | None,
) -> None:
    assert (
        GitHubAdvisoryThreatSource._normalize_cwe_id(
            raw_cwe
        )
        == expected
    )


def test_unit_preserves_github_cwe_details() -> None:
    advisory = {
        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        "cwes": [
            {
                "cwe_id": "79",
                "name": "Cross-site Scripting",
            }
        ],
    }

    source = GitHubAdvisoryThreatSource(
        connector=FakeGitHubAdvisoryConnector()
    )

    threat = source.parse([advisory])[0]

    assert threat.weaknesses == ["CWE-79"]

    assert threat.weakness_details == [
        {
            "cwe_id": "CWE-79",
            "name": "Cross-site Scripting",
            "source": "github_advisory",
            "is_official": False,
        }
    ]


def test_unit_cwe_without_name_is_still_preserved() -> None:
    advisory = {
        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        "cwes": [
            {
                "cwe_id": "CWE-89",
                "name": None,
            }
        ],
    }

    source = GitHubAdvisoryThreatSource(
        connector=FakeGitHubAdvisoryConnector()
    )

    threat = source.parse([advisory])[0]

    assert threat.weakness_details == [
        {
            "cwe_id": "CWE-89",
            "source": "github_advisory",
            "is_official": False,
        }
    ]


# ============================================================
# References, URLs and location tests
# ============================================================


def test_unit_references_are_deduplicated() -> None:
    advisory = {
        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        "references": [
            "https://example.com/advisory",
            {
                "url": "https://example.com/patch"
            },
            "https://example.com/advisory",
            {},
            None,
        ],
    }

    source = GitHubAdvisoryThreatSource(
        connector=FakeGitHubAdvisoryConnector()
    )

    threat = source.parse([advisory])[0]

    assert threat.references == [
        "https://example.com/advisory",
        "https://example.com/patch",
    ]


def test_unit_empty_source_urls_are_not_stored() -> None:
    advisory = {
        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        "url": "https://api.github.com/advisories/example",
        "html_url": "   ",
        "repository_advisory_url": None,
    }

    source = GitHubAdvisoryThreatSource(
        connector=FakeGitHubAdvisoryConnector()
    )

    threat = source.parse([advisory])[0]

    assert threat.source_urls == {
        "api": (
            "https://api.github.com/advisories/example"
        )
    }


def test_unit_source_code_locations_are_deduplicated() -> None:
    advisory = {
        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        "source_code_location": [
            "https://github.com/example/project",
            "https://github.com/example/project",
        ],
        "vulnerabilities": [
            {
                "source_code_location": {
                    "url": (
                        "https://github.com/example/project"
                    ),
                    "path": "src/vulnerable.py",
                    "location": "line 42",
                }
            }
        ],
    }

    source = GitHubAdvisoryThreatSource(
        connector=FakeGitHubAdvisoryConnector()
    )

    threat = source.parse([advisory])[0]

    assert threat.source_code_locations == [
        "https://github.com/example/project",
        "src/vulnerable.py",
        "line 42",
    ]


# ============================================================
# Date and severity tests
# ============================================================


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("critical", "CRITICAL"),
        (" HIGH ", "HIGH"),
        ("medium", "MEDIUM"),
        ("", None),
        (None, None),
        (123, None),
    ],
)
def test_unit_normalize_severity(
    value: Any,
    expected: str | None,
) -> None:
    assert (
        GitHubAdvisoryThreatSource._normalize_severity(
            value
        )
        == expected
    )


def test_unit_source_dates_ignore_missing_values() -> None:
    advisory = {
        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        "published_at": "2026-07-01T00:00:00Z",
        "updated_at": None,
        "github_reviewed_at": "   ",
        "withdrawn_at": None,
    }

    source = GitHubAdvisoryThreatSource(
        connector=FakeGitHubAdvisoryConnector()
    )

    threat = source.parse([advisory])[0]

    assert threat.source_dates == {
        "github_published_at": (
            "2026-07-01T00:00:00Z"
        )
    }


# ============================================================
# Parser robustness tests
# ============================================================


def test_unit_parse_rejects_non_list_raw_data() -> None:
    source = GitHubAdvisoryThreatSource(
        connector=FakeGitHubAdvisoryConnector()
    )

    with pytest.raises(
        ValueError,
        match="raw data must be a list",
    ):
        source.parse(
            {
                "ghsa_id": "GHSA-aaaa-bbbb-cccc"
            }
        )


def test_unit_parse_ignores_non_dictionary_elements() -> None:
    valid_advisory = {
        "ghsa_id": "GHSA-aaaa-bbbb-cccc"
    }

    source = GitHubAdvisoryThreatSource(
        connector=FakeGitHubAdvisoryConnector()
    )

    threats = source.parse(
        [
            None,
            "invalid",
            123,
            valid_advisory,
        ]
    )

    assert len(threats) == 1
    assert threats[0].id == "GHSA-aaaa-bbbb-cccc"


def test_unit_parse_empty_list_returns_empty_list() -> None:
    source = GitHubAdvisoryThreatSource(
        connector=FakeGitHubAdvisoryConnector()
    )

    assert source.parse([]) == []


# ============================================================
# CollectionResult tests
# ============================================================


def test_unit_collect_returns_collection_result(
    complete_advisory: dict[str, Any],
    ghsa_only_advisory: dict[str, Any],
) -> None:
    connector = FakeGitHubAdvisoryConnector(
        advisories=[
            complete_advisory,
            ghsa_only_advisory,
        ]
    )

    source = GitHubAdvisoryThreatSource(
        connector=connector,
        advisory_type="reviewed",
        ecosystem="maven",
        severity="critical",
        modified="2026-07-01..2026-07-10",
        per_page=25,
        max_pages=3,
    )

    result = source.collect()

    assert isinstance(result, CollectionResult)
    assert len(result.threats) == 2

    assert result.metadata["source"] == (
        "github_advisory"
    )
    assert result.metadata["api_version"] == (
        GitHubAdvisoryConnector.API_VERSION
    )
    assert result.metadata["advisory_type"] == (
        "reviewed"
    )
    assert result.metadata["ecosystem"] == "maven"
    assert result.metadata["severity"] == "critical"
    assert result.metadata["modified"] == (
        "2026-07-01..2026-07-10"
    )
    assert result.metadata["per_page"] == 25
    assert result.metadata["max_pages"] == 3
    assert result.metadata["collected_count"] == 2
    assert result.metadata["parsed_count"] == 2
    assert result.metadata["skipped_count"] == 0

    assert isinstance(
        result.metadata["collected_at"],
        str,
    )
    assert result.metadata["collected_at"]


def test_unit_collect_reports_skipped_advisories() -> None:
    valid_advisory = {
        "ghsa_id": "GHSA-aaaa-bbbb-cccc"
    }

    invalid_advisory = {
        "summary": "No usable identifier"
    }

    connector = FakeGitHubAdvisoryConnector(
        advisories=[
            valid_advisory,
            invalid_advisory,
        ]
    )

    source = GitHubAdvisoryThreatSource(
        connector=connector
    )

    result = source.collect()

    assert result.metadata["collected_count"] == 2
    assert result.metadata["parsed_count"] == 1
    assert result.metadata["skipped_count"] == 1


def test_unit_collect_with_empty_connector_result() -> None:
    source = GitHubAdvisoryThreatSource(
        connector=FakeGitHubAdvisoryConnector(
            advisories=[]
        )
    )

    result = source.collect()

    assert result.threats == []
    assert result.metadata["collected_count"] == 0
    assert result.metadata["parsed_count"] == 0
    assert result.metadata["skipped_count"] == 0

def test_unit_ignores_placeholder_cvss_v4_and_uses_v3():
    source = GitHubAdvisoryThreatSource()

    advisory = {
        "ghsa_id": "GHSA-jfh8-c2jp-5v3q",
        "cve_id": "CVE-2021-44228",
        "summary": "Remote code injection in Log4j",
        "description": "Log4Shell vulnerability",
        "severity": "critical",
        "type": "reviewed",
        "cvss_severities": {
            "cvss_v3": {
                "score": 10.0,
                "vector_string": (
                    "CVSS:3.1/AV:N/AC:L/PR:N/"
                    "UI:N/S:C/C:H/I:H/A:H"
                ),
            },
            "cvss_v4": {
                "score": 0.0,
                "vector_string": None,
            },
        },
    }

    threats = source.parse(
        [advisory]
    )

    assert len(threats) == 1

    threat = threats[0]

    assert threat.cvss_score == 10.0

    assert "3.1" in threat.cvss_metrics
    assert "4" not in threat.cvss_metrics

def test_unit_preserves_real_zero_cvss_when_vector_exists():
    source = GitHubAdvisoryThreatSource()

    advisory = {
        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        "summary": "Zero impact advisory",
        "description": "Example advisory",
        "severity": "low",
        "type": "reviewed",
        "cvss_severities": {
            "cvss_v4": {
                "score": 0.0,
                "vector_string": (
                    "CVSS:4.0/AV:N/AC:H/AT:P/"
                    "PR:H/UI:P/VC:N/VI:N/VA:N/"
                    "SC:N/SI:N/SA:N"
                ),
            },
        },
    }

    threats = source.parse(
        [advisory]
    )

    assert len(threats) == 1

    threat = threats[0]

    assert threat.cvss_score == 0.0
    assert "4.0" in threat.cvss_metrics
    
def test_unit_prefers_positive_cvss_v4_over_v3():
    source = GitHubAdvisoryThreatSource()

    advisory = {
        "ghsa_id": "GHSA-1111-2222-3333",
        "summary": "Example advisory",
        "description": "Example vulnerability",
        "severity": "high",
        "type": "reviewed",
        "cvss_severities": {
            "cvss_v3": {
                "score": 8.8,
                "vector_string": (
                    "CVSS:3.1/AV:N/AC:L/PR:L/"
                    "UI:N/S:U/C:H/I:H/A:H"
                ),
            },
            "cvss_v4": {
                "score": 9.1,
                "vector_string": (
                    "CVSS:4.0/AV:N/AC:L/AT:N/"
                    "PR:L/UI:N/VC:H/VI:H/VA:H/"
                    "SC:N/SI:N/SA:N"
                ),
            },
        },
    }

    threats = source.parse(
        [advisory]
    )

    threat = threats[0]

    assert threat.cvss_score == 9.1
    assert "3.1" in threat.cvss_metrics
    assert "4.0" in threat.cvss_metrics