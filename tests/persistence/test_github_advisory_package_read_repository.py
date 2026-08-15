from __future__ import annotations

from unittest.mock import Mock

import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Session

from application.ports.outbound.github_advisory_package_read_repository import (
    GitHubAdvisoryPackageKey,
)
from infrastructure.persistence.sqlalchemy.repositories.github_advisory_package_read_repository import (
    SqlAlchemyGitHubAdvisoryPackageReadRepository,
)


def _repository(
) -> tuple[
    SqlAlchemyGitHubAdvisoryPackageReadRepository,
    Mock,
]:
    session = Mock(
        spec=Session,
    )

    repository = (
        SqlAlchemyGitHubAdvisoryPackageReadRepository(
            session=session,
        )
    )

    return (
        repository,
        session,
    )


def test_empty_keys_returns_without_query() -> None:
    repository, session = (
        _repository()
    )

    result = repository.find_candidates(
        package_keys=[],
    )

    assert result == ()
    session.execute.assert_not_called()


def test_returns_requested_pypi_candidate() -> None:
    repository, session = (
        _repository()
    )

    session.execute.return_value.all.return_value = [
        (
            "GHSA-aaaa-bbbb-cccc",
            "CVE-2026-12345",
            "HIGH",
            [
                {
                    "ecosystem": "pip",
                    "package_name": (
                        "Requests_Security.Test"
                    ),
                    "vulnerable_version_range": (
                        ">= 1.0, < 2.0"
                    ),
                    "first_patched_version": (
                        "2.0"
                    ),
                },
                {
                    "ecosystem": "pip",
                    "package_name": "other",
                    "vulnerable_version_range": (
                        "< 9.0"
                    ),
                    "first_patched_version": None,
                },
            ],
        )
    ]

    result = repository.find_candidates(
        package_keys=[
            GitHubAdvisoryPackageKey(
                ecosystem="pypi",
                package_name=(
                    "requests-security-test"
                ),
            )
        ],
    )

    assert len(result) == 1

    candidate = result[0]

    assert candidate.ghsa_id == (
        "GHSA-aaaa-bbbb-cccc"
    )

    assert candidate.cve_id == (
        "CVE-2026-12345"
    )

    assert candidate.ecosystem == "pip"

    assert candidate.package_name == (
        "Requests_Security.Test"
    )

    assert (
        candidate.vulnerable_version_range
        == ">= 1.0, < 2.0"
    )

    assert (
        candidate.first_patched_version
        == "2.0"
    )

    assert candidate.severity == "HIGH"

    session.execute.assert_called_once()


def test_malformed_package_entry_is_ignored() -> None:
    repository, session = (
        _repository()
    )

    session.execute.return_value.all.return_value = [
        (
            "GHSA-aaaa-bbbb-cccc",
            None,
            "LOW",
            [
                {
                    "ecosystem": "pip",
                    "package_name": "requests",
                    "vulnerable_version_range": None,
                    "first_patched_version": None,
                }
            ],
        )
    ]

    result = repository.find_candidates(
        package_keys=[
            GitHubAdvisoryPackageKey(
                ecosystem="pypi",
                package_name="requests",
            )
        ],
    )

    assert result == ()


def test_duplicate_candidates_are_deduplicated() -> None:
    repository, session = (
        _repository()
    )

    affected_packages = [
        {
            "ecosystem": "pip",
            "package_name": "requests",
            "vulnerable_version_range": (
                "< 3.0"
            ),
            "first_patched_version": "3.0",
        }
    ]

    row = (
        "GHSA-aaaa-bbbb-cccc",
        "CVE-2026-12345",
        "HIGH",
        affected_packages,
    )

    session.execute.return_value.all.return_value = [
        row,
        row,
    ]

    result = repository.find_candidates(
        package_keys=[
            GitHubAdvisoryPackageKey(
                ecosystem="pypi",
                package_name="requests",
            )
        ],
    )

    assert len(result) == 1


def test_multiple_keys_use_one_query_inside_batch() -> None:
    repository, session = (
        _repository()
    )

    session.execute.return_value.all.return_value = []

    repository.find_candidates(
        package_keys=[
            GitHubAdvisoryPackageKey(
                ecosystem="pypi",
                package_name="requests",
            ),
            GitHubAdvisoryPackageKey(
                ecosystem="pypi",
                package_name="urllib3",
            ),
            GitHubAdvisoryPackageKey(
                ecosystem="npm",
                package_name="@scope/package",
            ),
        ],
    )

    assert session.execute.call_count == 1


def test_large_key_set_is_batched() -> None:
    repository, session = (
        _repository()
    )

    session.execute.return_value.all.return_value = []

    keys = [
        GitHubAdvisoryPackageKey(
            ecosystem="pypi",
            package_name=f"package-{index}",
        )
        for index in range(
            repository.BATCH_SIZE + 1
        )
    ]

    repository.find_candidates(
        package_keys=keys,
    )

    assert session.execute.call_count == 2


def test_statement_filters_with_jsonb_and_withdrawn() -> None:
    statement = (
        SqlAlchemyGitHubAdvisoryPackageReadRepository
        ._build_statement(
            (
                GitHubAdvisoryPackageKey(
                    ecosystem="pypi",
                    package_name="requests",
                ),
            )
        )
    )

    compiled = str(
        statement.compile(
            dialect=postgresql.dialect(),
        )
    )

    assert (
        "jsonb_array_elements"
        in compiled
    )

    assert (
        "regexp_replace"
        in compiled
    )

    assert (
        "withdrawn_at IS NULL"
        in compiled
    )


def test_constructor_rejects_missing_session() -> None:
    with pytest.raises(
        ValueError,
        match="session must not be None",
    ):
        (
            SqlAlchemyGitHubAdvisoryPackageReadRepository(
                session=None,  # type: ignore[arg-type]
            )
        )


def test_invalid_key_type_is_rejected() -> None:
    repository, _ = (
        _repository()
    )

    with pytest.raises(
        TypeError,
        match="GitHubAdvisoryPackageKey",
    ):
        repository.find_candidates(
            package_keys=[
                object(),  # type: ignore[list-item]
            ],
        )


def test_unsupported_ecosystem_is_rejected() -> None:
    repository, _ = (
        _repository()
    )

    with pytest.raises(
        ValueError,
        match="ecosystem must be one of",
    ):
        repository.find_candidates(
            package_keys=[
                GitHubAdvisoryPackageKey(
                    ecosystem="maven",
                    package_name="example",
                )
            ],
        )