from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from application.services.github_advisory_normalizer import (
    GitHubAdvisoryNormalizationError,
    GitHubAdvisoryNormalizer,
)


@pytest.fixture
def raw_payload_id() -> UUID:
    return uuid4()


@pytest.fixture
def complete_advisory() -> dict[str, object]:
    package = {
        "package": {
            "ecosystem": " maven ",
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
            "lookup",
            "lookup",
        ],
        "source_code_location": {
            "url": (
                "https://github.com/apache/"
                "logging-log4j2"
            ),
            "path": "src/JndiLookup.java",
        },
    }

    return {
        "ghsa_id": "GHSA-JFH8-C2JP-5V3Q",
        "cve_id": "cve-2021-44228",
        "type": " Reviewed ",
        "severity": " critical ",
        "summary": (
            " Log4Shell vulnerability "
        ),
        "description": (
            "Remote code execution in Log4j."
        ),
        "published_at": (
            "2021-12-10T00:00:00Z"
        ),
        "updated_at": (
            "2023-01-01T00:00:00+00:00"
        ),
        "github_reviewed_at": (
            "2021-12-10T12:00:00Z"
        ),
        "withdrawn_at": None,
        "cvss_severities": {
            "cvss_v3": {
                "score": 10.0,
                "vector_string": (
                    "CVSS:3.1/AV:N/AC:L"
                ),
            },
            "cvss_v4": {
                "score": 9.3,
                "vector_string": (
                    "CVSS:4.0/AV:N/AC:L"
                ),
            },
        },
        "epss": {
            "percentage": "0.94321",
            "percentile": 0.9999,
        },
        "vulnerabilities": [
            package,
            deepcopy(package),
        ],
        "cwes": [
            {
                "cwe_id": "CWE-502",
            },
            {
                "cwe_id": "cwe-20",
            },
            "CWE-502",
            "NVD-CWE-noinfo",
            "CWE-79: Cross-site scripting",
        ],
        "references": [
            (
                "https://github.com/advisories/"
                "GHSA-jfh8-c2jp-5v3q"
            ),
            {
                "url": (
                    "https://nvd.nist.gov/vuln/"
                    "detail/CVE-2021-44228"
                ),
            },
            (
                "https://github.com/advisories/"
                "GHSA-jfh8-c2jp-5v3q"
            ),
            (
                "https://user:secret@"
                "example.com/private"
            ),
            "javascript:alert(1)",
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
            (
                "https://github.com/apache/"
                "logging-log4j2"
            ),
        ],
    }


def test_normalize_maps_complete_advisory(
    raw_payload_id: UUID,
    complete_advisory: dict[str, object],
) -> None:
    result = (
        GitHubAdvisoryNormalizer()
        .normalize(
            raw_payload_id=raw_payload_id,
            payload=complete_advisory,
        )
    )

    assert (
        result.raw_payload_id
        == raw_payload_id
    )

    assert result.ghsa_id == (
        "GHSA-jfh8-c2jp-5v3q"
    )

    assert (
        result.cve_id
        == "CVE-2021-44228"
    )

    assert (
        result.advisory_type
        == "reviewed"
    )

    assert result.severity == "CRITICAL"

    assert result.summary == (
        "Log4Shell vulnerability"
    )

    assert result.description == (
        "Remote code execution in Log4j."
    )

    assert result.published_at == datetime(
        2021,
        12,
        10,
        tzinfo=UTC,
    )

    assert result.updated_at == datetime(
        2023,
        1,
        1,
        tzinfo=UTC,
    )

    assert result.cvss_score == 9.3

    assert [
        metric.version
        for metric in result.cvss_metrics
    ] == [
        "3.1",
        "4.0",
    ]

    assert result.epss_score == (
        pytest.approx(0.94321)
    )

    assert result.epss_percentile == (
        pytest.approx(0.9999)
    )

    assert (
        len(result.affected_packages)
        == 1
    )

    package = result.affected_packages[0]

    assert package.ecosystem == "maven"

    assert package.package_name == (
        "org.apache.logging.log4j:"
        "log4j-core"
    )

    assert (
        package.vulnerable_functions
        == ("lookup",)
    )

    assert (
        package.source_code_locations
        == (
            "https://github.com/apache/"
            "logging-log4j2",
            "src/JndiLookup.java",
        )
    )

    assert result.cwe_ids == (
        "CWE-502",
        "CWE-20",
        "CWE-79",
    )

    assert result.references == (
        "https://github.com/advisories/"
        "GHSA-jfh8-c2jp-5v3q",
        "https://nvd.nist.gov/vuln/"
        "detail/CVE-2021-44228",
    )

    assert (
        result.normalizer_version
        == "1.0.0"
    )


def test_cve_is_read_from_identifiers(
    raw_payload_id: UUID,
) -> None:
    result = (
        GitHubAdvisoryNormalizer()
        .normalize(
            raw_payload_id=raw_payload_id,
            payload={
                "ghsa_id": (
                    "GHSA-aaaa-bbbb-cccc"
                ),
                "cve_id": None,
                "identifiers": [
                    {
                        "type": "cve",
                        "value": (
                            "cve-2026-12345"
                        ),
                    },
                ],
            },
        )
    )

    assert (
        result.cve_id
        == "CVE-2026-12345"
    )


@pytest.mark.parametrize(
    "invalid_ghsa_id",
    [
        None,
        "",
        "GHSA-invalid",
        "CVE-2026-12345",
        123,
    ],
)
def test_invalid_ghsa_id_is_rejected(
    raw_payload_id: UUID,
    invalid_ghsa_id: object,
) -> None:
    with pytest.raises(
        GitHubAdvisoryNormalizationError,
        match="ghsa_id",
    ):
        GitHubAdvisoryNormalizer().normalize(
            raw_payload_id=raw_payload_id,
            payload={
                "ghsa_id": invalid_ghsa_id,
            },
        )


def test_invalid_direct_cve_is_rejected(
    raw_payload_id: UUID,
) -> None:
    with pytest.raises(
        GitHubAdvisoryNormalizationError,
        match="cve_id",
    ):
        GitHubAdvisoryNormalizer().normalize(
            raw_payload_id=raw_payload_id,
            payload={
                "ghsa_id": (
                    "GHSA-aaaa-bbbb-cccc"
                ),
                "cve_id": "invalid",
            },
        )


def test_legacy_cvss_is_used_without_usable_v3(
    raw_payload_id: UUID,
) -> None:
    result = (
        GitHubAdvisoryNormalizer()
        .normalize(
            raw_payload_id=raw_payload_id,
            payload={
                "ghsa_id": (
                    "GHSA-aaaa-bbbb-cccc"
                ),
                "cvss_severities": {
                    "cvss_v4": {
                        "score": 0.0,
                        "vector_string": None,
                    },
                },
                "cvss": {
                    "score": "8.8",
                    "vector_string": (
                        "CVSS:3.1/AV:N"
                    ),
                },
            },
        )
    )

    assert result.cvss_score == 8.8

    assert [
        metric.version
        for metric in result.cvss_metrics
    ] == ["3.1"]


def test_real_zero_cvss_with_vector_is_kept(
    raw_payload_id: UUID,
) -> None:
    result = (
        GitHubAdvisoryNormalizer()
        .normalize(
            raw_payload_id=raw_payload_id,
            payload={
                "ghsa_id": (
                    "GHSA-aaaa-bbbb-cccc"
                ),
                "cvss": {
                    "score": 0.0,
                    "vector_string": (
                        "CVSS:3.1/AV:P/AC:H"
                    ),
                },
            },
        )
    )

    assert result.cvss_score == 0.0

    assert (
        len(result.cvss_metrics)
        == 1
    )


def test_invalid_optional_scores_are_ignored(
    raw_payload_id: UUID,
) -> None:
    result = (
        GitHubAdvisoryNormalizer()
        .normalize(
            raw_payload_id=raw_payload_id,
            payload={
                "ghsa_id": (
                    "GHSA-aaaa-bbbb-cccc"
                ),
                "cvss": {
                    "score": True,
                    "vector_string": None,
                },
                "epss": {
                    "percentage": 1.5,
                    "percentile": True,
                },
            },
        )
    )

    assert result.cvss_score is None
    assert result.cvss_metrics == ()
    assert result.epss_score is None
    assert result.epss_percentile is None


def test_optional_fields_can_be_missing(
    raw_payload_id: UUID,
) -> None:
    result = (
        GitHubAdvisoryNormalizer()
        .normalize(
            raw_payload_id=raw_payload_id,
            payload={
                "ghsa_id": (
                    "GHSA-aaaa-bbbb-cccc"
                ),
            },
        )
    )

    assert result.cve_id is None
    assert result.affected_packages == ()
    assert result.cwe_ids == ()
    assert result.references == ()


def test_naive_timestamp_is_rejected(
    raw_payload_id: UUID,
) -> None:
    with pytest.raises(
        GitHubAdvisoryNormalizationError,
        match="timezone",
    ):
        GitHubAdvisoryNormalizer().normalize(
            raw_payload_id=raw_payload_id,
            payload={
                "ghsa_id": (
                    "GHSA-aaaa-bbbb-cccc"
                ),
                "published_at": (
                    "2026-07-29T10:00:00"
                ),
            },
        )


def test_input_payload_is_not_modified(
    raw_payload_id: UUID,
    complete_advisory: dict[str, object],
) -> None:
    original = deepcopy(
        complete_advisory
    )

    GitHubAdvisoryNormalizer().normalize(
        raw_payload_id=raw_payload_id,
        payload=complete_advisory,
    )

    assert complete_advisory == original


def test_invalid_raw_payload_id_is_rejected(
) -> None:
    with pytest.raises(
        TypeError,
        match="raw_payload_id",
    ):
        GitHubAdvisoryNormalizer().normalize(
            raw_payload_id=(
                "invalid"  # type: ignore[arg-type]
            ),
            payload={
                "ghsa_id": (
                    "GHSA-aaaa-bbbb-cccc"
                ),
            },
        )


def test_non_mapping_payload_is_rejected(
    raw_payload_id: UUID,
) -> None:
    with pytest.raises(
        TypeError,
        match="payload",
    ):
        GitHubAdvisoryNormalizer().normalize(
            raw_payload_id=raw_payload_id,
            payload=[],  # type: ignore[arg-type]
        )


def test_collection_size_is_bounded(
    raw_payload_id: UUID,
) -> None:
    with pytest.raises(
        GitHubAdvisoryNormalizationError,
        match="too many",
    ):
        GitHubAdvisoryNormalizer().normalize(
            raw_payload_id=raw_payload_id,
            payload={
                "ghsa_id": (
                    "GHSA-aaaa-bbbb-cccc"
                ),
                "cwes": [
                    "CWE-79"
                    for _ in range(101)
                ],
            },
        )