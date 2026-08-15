from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from application.services.github_advisory_canonical_match_resolver import (
    GitHubAdvisoryCanonicalMatchResolver,
    GitHubAdvisoryCanonicalResolutionConflictError,
)
from application.services.github_advisory_package_matcher import (
    GitHubAdvisoryPackageMatch,
)
from domain.canonical_vulnerability import (
    CanonicalVulnerability,
)
from domain.vulnerability_evidence import (
    VulnerabilityEvidence,
)
from domain.vulnerability_identifier import (
    VulnerabilityIdentifier,
)


NOW = datetime(
    2026,
    8,
    15,
    15,
    0,
    tzinfo=UTC,
)


class FakeCanonicalVulnerabilityRepository:
    def __init__(
        self,
        *,
        vulnerabilities_by_key: dict[
            tuple[str, str],
            CanonicalVulnerability,
        ],
    ) -> None:
        self.vulnerabilities_by_key = (
            vulnerabilities_by_key
        )

        self.find_many_call_count = 0

        self.requested_identifiers: tuple[
            VulnerabilityIdentifier,
            ...,
        ] = ()

    def find_many_by_identifiers(
        self,
        identifiers,
    ):
        self.find_many_call_count += 1

        self.requested_identifiers = tuple(
            identifiers
        )

        return {
            identifier.key: (
                self.vulnerabilities_by_key[
                    identifier.key
                ]
            )
            for identifier
            in self.requested_identifiers
            if identifier.key
            in self.vulnerabilities_by_key
        }


def _canonical(
    *,
    cve_id: str | None = None,
    ghsa_id: str,
    status: str = "active",
) -> CanonicalVulnerability:
    identifiers: list[
        VulnerabilityIdentifier
    ] = []

    if cve_id is not None:
        identifiers.append(
            VulnerabilityIdentifier(
                namespace="CVE",
                value=cve_id,
                is_primary=True,
            )
        )

        identifiers.append(
            VulnerabilityIdentifier(
                namespace="GHSA",
                value=ghsa_id,
                is_primary=False,
            )
        )

    else:
        identifiers.append(
            VulnerabilityIdentifier(
                namespace="GHSA",
                value=ghsa_id,
                is_primary=True,
            )
        )

    return CanonicalVulnerability(
        id=uuid4(),
        identifiers=tuple(
            identifiers
        ),
        evidences=(
            VulnerabilityEvidence(
                source="github_advisory",
                source_record_key=(
                    ghsa_id
                ),
                normalized_record_id=(
                    str(uuid4())
                ),
                evidence_type=(
                    "github_security_advisory"
                ),
                correlation_rule=(
                    "exact_ghsa"
                ),
                observed_at=NOW,
            ),
        ),
        created_at=NOW,
        updated_at=NOW,
        status=status,
    )


def _match(
    *,
    component_id: UUID | None = None,
    ghsa_id: str = (
        "GHSA-AAAA-BBBB-CCCC"
    ),
    cve_id: str | None = (
        "CVE-2026-12345"
    ),
) -> GitHubAdvisoryPackageMatch:
    return GitHubAdvisoryPackageMatch(
        software_component_id=(
            component_id or uuid4()
        ),
        ghsa_id=ghsa_id,
        cve_id=cve_id,
        applicability_status="confirmed",
        match_rule=(
            "github_advisory_pypi_"
            "exact_package_version_range_v1"
        ),
        match_version="1.5.0",
        vulnerable_version_range=(
            ">= 1.0, < 2.0"
        ),
        first_patched_version="2.0",
        severity="HIGH",
    )


def test_resolves_cve_and_ghsa_to_same_canonical() -> None:
    canonical = _canonical(
        cve_id="CVE-2026-12345",
        ghsa_id=(
            "GHSA-AAAA-BBBB-CCCC"
        ),
    )

    repository = (
        FakeCanonicalVulnerabilityRepository(
            vulnerabilities_by_key={
                (
                    "CVE",
                    "CVE-2026-12345",
                ): canonical,
                (
                    "GHSA",
                    "GHSA-AAAA-BBBB-CCCC",
                ): canonical,
            }
        )
    )

    resolver = (
        GitHubAdvisoryCanonicalMatchResolver(
            canonical_vulnerability_repository=(
                repository  # type: ignore[arg-type]
            ),
        )
    )

    result = resolver.resolve(
        matches=[
            _match()
        ]
    )

    assert len(result.resolved) == 1
    assert result.unresolved == ()

    assert (
        result.resolved[0]
        .canonical_vulnerability_id
        == canonical.id
    )

    assert (
        repository.find_many_call_count
        == 1
    )


def test_falls_back_to_ghsa_when_cve_is_not_found() -> None:
    canonical = _canonical(
        ghsa_id=(
            "GHSA-AAAA-BBBB-CCCC"
        ),
    )

    repository = (
        FakeCanonicalVulnerabilityRepository(
            vulnerabilities_by_key={
                (
                    "GHSA",
                    "GHSA-AAAA-BBBB-CCCC",
                ): canonical,
            }
        )
    )

    resolver = (
        GitHubAdvisoryCanonicalMatchResolver(
            canonical_vulnerability_repository=(
                repository  # type: ignore[arg-type]
            ),
        )
    )

    result = resolver.resolve(
        matches=[
            _match()
        ]
    )

    assert len(result.resolved) == 1

    assert (
        result.resolved[0]
        .canonical_vulnerability_id
        == canonical.id
    )


def test_missing_canonical_is_reported_as_unresolved() -> None:
    repository = (
        FakeCanonicalVulnerabilityRepository(
            vulnerabilities_by_key={}
        )
    )

    resolver = (
        GitHubAdvisoryCanonicalMatchResolver(
            canonical_vulnerability_repository=(
                repository  # type: ignore[arg-type]
            ),
        )
    )

    match = _match()

    result = resolver.resolve(
        matches=[
            match
        ]
    )

    assert result.resolved == ()
    assert result.unresolved == (
        match,
    )


def test_cve_and_ghsa_conflict_is_rejected() -> None:
    cve_canonical = _canonical(
        cve_id="CVE-2026-12345",
        ghsa_id=(
            "GHSA-1111-2222-3333"
        ),
    )

    ghsa_canonical = _canonical(
        ghsa_id=(
            "GHSA-AAAA-BBBB-CCCC"
        ),
    )

    repository = (
        FakeCanonicalVulnerabilityRepository(
            vulnerabilities_by_key={
                (
                    "CVE",
                    "CVE-2026-12345",
                ): cve_canonical,
                (
                    "GHSA",
                    "GHSA-AAAA-BBBB-CCCC",
                ): ghsa_canonical,
            }
        )
    )

    resolver = (
        GitHubAdvisoryCanonicalMatchResolver(
            canonical_vulnerability_repository=(
                repository  # type: ignore[arg-type]
            ),
        )
    )

    with pytest.raises(
        GitHubAdvisoryCanonicalResolutionConflictError
    ):
        resolver.resolve(
            matches=[
                _match()
            ]
        )


@pytest.mark.parametrize(
    "status",
    [
        "withdrawn",
        "rejected",
    ],
)
def test_non_actionable_canonical_is_unresolved(
    status: str,
) -> None:
    canonical = _canonical(
        cve_id="CVE-2026-12345",
        ghsa_id=(
            "GHSA-AAAA-BBBB-CCCC"
        ),
        status=status,
    )

    repository = (
        FakeCanonicalVulnerabilityRepository(
            vulnerabilities_by_key={
                (
                    "CVE",
                    "CVE-2026-12345",
                ): canonical,
                (
                    "GHSA",
                    "GHSA-AAAA-BBBB-CCCC",
                ): canonical,
            }
        )
    )

    resolver = (
        GitHubAdvisoryCanonicalMatchResolver(
            canonical_vulnerability_repository=(
                repository  # type: ignore[arg-type]
            ),
        )
    )

    match = _match()

    result = resolver.resolve(
        matches=[
            match
        ]
    )

    assert result.resolved == ()
    assert result.unresolved == (
        match,
    )


def test_multiple_matches_use_single_batch_lookup() -> None:
    first = _canonical(
        cve_id="CVE-2026-12345",
        ghsa_id=(
            "GHSA-AAAA-BBBB-CCCC"
        ),
    )

    second = _canonical(
        cve_id="CVE-2026-54321",
        ghsa_id=(
            "GHSA-DDDD-EEEE-FFFF"
        ),
    )

    repository = (
        FakeCanonicalVulnerabilityRepository(
            vulnerabilities_by_key={
                (
                    "CVE",
                    "CVE-2026-12345",
                ): first,
                (
                    "GHSA",
                    "GHSA-AAAA-BBBB-CCCC",
                ): first,
                (
                    "CVE",
                    "CVE-2026-54321",
                ): second,
                (
                    "GHSA",
                    "GHSA-DDDD-EEEE-FFFF",
                ): second,
            }
        )
    )

    resolver = (
        GitHubAdvisoryCanonicalMatchResolver(
            canonical_vulnerability_repository=(
                repository  # type: ignore[arg-type]
            ),
        )
    )

    result = resolver.resolve(
        matches=[
            _match(),
            _match(
                ghsa_id=(
                    "GHSA-DDDD-EEEE-FFFF"
                ),
                cve_id=(
                    "CVE-2026-54321"
                ),
            ),
        ]
    )

    assert len(result.resolved) == 2

    # Une seule lecture batch du repository.
    assert (
        repository.find_many_call_count
        == 1
    )


def test_empty_matches_do_not_query_repository() -> None:
    repository = (
        FakeCanonicalVulnerabilityRepository(
            vulnerabilities_by_key={}
        )
    )

    resolver = (
        GitHubAdvisoryCanonicalMatchResolver(
            canonical_vulnerability_repository=(
                repository  # type: ignore[arg-type]
            ),
        )
    )

    result = resolver.resolve(
        matches=[]
    )

    assert result.resolved == ()
    assert result.unresolved == ()

    assert (
        repository.find_many_call_count
        == 0
    )