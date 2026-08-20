from __future__ import annotations

from datetime import (
    UTC,
    datetime,
)
from uuid import uuid4

import pytest

from application.ports.outbound.github_advisory_package_read_repository import (
    GitHubAdvisoryPackageCandidate,
)
from application.services.github_advisory_package_matcher import (
    GitHubAdvisoryPackageMatcher,
)
from domain.software_component import (
    SoftwareComponent,
)


NOW = datetime(
    2026,
    8,
    15,
    14,
    0,
    tzinfo=UTC,
)


def _package(
    *,
    name: str = "requests",
    normalized_name: str = "requests",
    version: str = "2.31.0",
    ecosystem: str = "pypi",
) -> SoftwareComponent:
    detected_by = (
        "pip_global"
        if ecosystem == "pypi"
        else "npm_global"
    )

    return SoftwareComponent(
        id=uuid4(),
        machine_id=uuid4(),
        component_type="package",
        name=name,
        normalized_name=(
            normalized_name
        ),
        version=version,
        vendor=None,
        normalized_vendor=None,
        ecosystem=ecosystem,
        external_id=None,
        scope="global",
        detected_by=detected_by,
        created_at=NOW,
        updated_at=NOW,
    )


def _candidate(
    *,
    package_name: str = "requests",
    vulnerable_version_range: str = (
        ">= 2.0.0, < 2.32.0"
    ),
    ghsa_id: str = (
        "GHSA-aaaa-bbbb-cccc"
    ),
    cve_id: str | None = (
        "CVE-2026-12345"
    ),
    ecosystem: str = "pip",
    severity: str | None = "high",
) -> GitHubAdvisoryPackageCandidate:
    return GitHubAdvisoryPackageCandidate(
        ghsa_id=ghsa_id,
        cve_id=cve_id,
        ecosystem=ecosystem,
        package_name=package_name,
        vulnerable_version_range=(
            vulnerable_version_range
        ),
        first_patched_version=(
            "2.32.0"
        ),
        severity=severity,
    )


@pytest.mark.parametrize(
    (
        "github_severity",
        "expected_severity",
    ),
    [
        (
            "moderate",
            "MEDIUM",
        ),
        (
            "unknown",
            None,
        ),
    ],
)
def test_github_severity_is_mapped_to_platform_severity(
    github_severity: str,
    expected_severity: str | None,
) -> None:
    matches = (
        GitHubAdvisoryPackageMatcher()
        .match(
            component=_package(),
            candidates=[
                _candidate(
                    severity=(
                        github_severity
                    )
                )
            ],
        )
    )

    assert len(matches) == 1

    assert (
        matches[0].severity
        == expected_severity
    )


def test_confirmed_pypi_match_when_version_is_vulnerable(
) -> None:
    component = _package()

    matcher = (
        GitHubAdvisoryPackageMatcher()
    )

    matches = matcher.match(
        component=component,
        candidates=[
            _candidate()
        ],
    )

    assert len(matches) == 1

    match = matches[0]

    assert (
        match.software_component_id
        == component.id
    )

    assert (
        match.applicability_status
        == "confirmed"
    )

    assert (
        match.match_version
        == "2.31.0"
    )

    assert (
        match.match_rule
        == (
            GitHubAdvisoryPackageMatcher
            .MATCH_RULE_PYPI
        )
    )

    assert match.ghsa_id == (
        "GHSA-AAAA-BBBB-CCCC"
    )

    assert match.cve_id == (
        "CVE-2026-12345"
    )

    assert (
        match.severity
        == "HIGH"
    )


def test_confirmed_npm_match_when_version_is_vulnerable(
) -> None:
    component = _package(
        name="lodash",
        normalized_name="lodash",
        version="4.17.20",
        ecosystem="npm",
    )

    candidate = _candidate(
        package_name="lodash",
        vulnerable_version_range=(
            ">= 4.0.0, < 4.17.21"
        ),
        ecosystem="npm",
    )

    matches = (
        GitHubAdvisoryPackageMatcher()
        .match(
            component=component,
            candidates=[
                candidate
            ],
        )
    )

    assert len(matches) == 1

    match = matches[0]

    assert (
        match.software_component_id
        == component.id
    )

    assert (
        match.applicability_status
        == "confirmed"
    )

    assert (
        match.match_version
        == "4.17.20"
    )

    assert (
        match.match_rule
        == (
            GitHubAdvisoryPackageMatcher
            .MATCH_RULE_NPM
        )
    )


def test_npm_scoped_package_name_matches_exactly_after_normalization(
) -> None:
    component = _package(
        name="@Example/Package",
        normalized_name=(
            "@example/package"
        ),
        version="1.2.0",
        ecosystem="npm",
    )

    candidate = _candidate(
        package_name=(
            "@EXAMPLE/PACKAGE"
        ),
        vulnerable_version_range=(
            ">= 1.0.0, < 2.0.0"
        ),
        ecosystem="npm",
    )

    matches = (
        GitHubAdvisoryPackageMatcher()
        .match(
            component=component,
            candidates=[
                candidate
            ],
        )
    )

    assert len(matches) == 1


def test_npm_name_does_not_use_pypi_separator_normalization(
) -> None:
    component = _package(
        name="example-package",
        normalized_name=(
            "example-package"
        ),
        version="1.0.0",
        ecosystem="npm",
    )

    candidate = _candidate(
        package_name=(
            "example_package"
        ),
        vulnerable_version_range=(
            ">= 0.1.0, < 2.0.0"
        ),
        ecosystem="npm",
    )

    matches = (
        GitHubAdvisoryPackageMatcher()
        .match(
            component=component,
            candidates=[
                candidate
            ],
        )
    )

    assert matches == ()


def test_first_patched_version_is_not_vulnerable(
) -> None:
    component = _package(
        version="2.32.0"
    )

    matches = (
        GitHubAdvisoryPackageMatcher()
        .match(
            component=component,
            candidates=[
                _candidate()
            ],
        )
    )

    assert matches == ()


def test_package_name_uses_exact_pypi_normalization(
) -> None:
    component = _package(
        name="Requests-Security-Test",
        normalized_name=(
            "requests-security-test"
        ),
    )

    candidate = _candidate(
        package_name=(
            "Requests_Security.Test"
        ),
    )

    matches = (
        GitHubAdvisoryPackageMatcher()
        .match(
            component=component,
            candidates=[
                candidate
            ],
        )
    )

    assert len(matches) == 1


def test_different_package_does_not_match(
) -> None:
    component = _package()

    matches = (
        GitHubAdvisoryPackageMatcher()
        .match(
            component=component,
            candidates=[
                _candidate(
                    package_name=(
                        "urllib3"
                    )
                )
            ],
        )
    )

    assert matches == ()


def test_candidate_ecosystem_must_match_component_ecosystem(
) -> None:
    component = _package(
        name="example",
        normalized_name="example",
        version="1.0.0",
        ecosystem="npm",
    )

    candidate = _candidate(
        package_name="example",
        vulnerable_version_range=(
            ">= 0.1.0, < 2.0.0"
        ),
        ecosystem="pypi",
    )

    matches = (
        GitHubAdvisoryPackageMatcher()
        .match(
            component=component,
            candidates=[
                candidate
            ],
        )
    )

    assert matches == ()


def test_invalid_vulnerable_range_is_not_confirmed(
) -> None:
    component = _package()

    matches = (
        GitHubAdvisoryPackageMatcher()
        .match(
            component=component,
            candidates=[
                _candidate(
                    vulnerable_version_range=(
                        "not-a-version-range"
                    )
                )
            ],
        )
    )

    assert matches == ()


def test_simple_equality_range_is_supported(
) -> None:
    component = _package(
        version="2.31.0"
    )

    matches = (
        GitHubAdvisoryPackageMatcher()
        .match(
            component=component,
            candidates=[
                _candidate(
                    vulnerable_version_range=(
                        "= 2.31.0"
                    )
                )
            ],
        )
    )

    assert len(matches) == 1


def test_duplicate_ghsa_is_returned_once(
) -> None:
    component = _package()

    candidate = _candidate()

    matches = (
        GitHubAdvisoryPackageMatcher()
        .match(
            component=component,
            candidates=[
                candidate,
                candidate,
            ],
        )
    )

    assert len(matches) == 1


def test_invalid_installed_version_is_not_confirmed(
) -> None:
    component = _package(
        version="not-a-valid-version"
    )

    matches = (
        GitHubAdvisoryPackageMatcher()
        .match(
            component=component,
            candidates=[
                _candidate()
            ],
        )
    )

    assert matches == ()