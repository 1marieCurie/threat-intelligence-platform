from __future__ import annotations

from datetime import date
from types import TracebackType
from typing import Any

import pytest

from application.models.epss_snapshot import (
    EPSSSnapshot,
)
from application.services.epss_lookup_service import (
    EPSSLookupService,
)


class FakeEPSSRepository:
    """
    Repository EPSS déterministe sans accès PostgreSQL.

    Le résultat reste volontairement typé comme object
    afin de pouvoir simuler un adaptateur défectueux.
    """

    def __init__(
        self,
        *,
        result: object | None = None,
        error: Exception | None = None,
    ) -> None:
        self.result = (
            {}
            if result is None
            else result
        )
        self.error = error

        self.calls: list[
            list[str]
        ] = []

    def find_many_by_cve_ids(
        self,
        cve_ids: list[str],
    ) -> object:
        self.calls.append(
            list(cve_ids)
        )

        if self.error is not None:
            raise self.error

        return self.result


class FakeUnitOfWork:
    """
    Unit of Work déterministe limité au cas d'usage EPSS.
    """

    def __init__(
        self,
        repository: FakeEPSSRepository,
    ) -> None:
        self.epss_scores: Any = repository

        self.enter_count = 0
        self.exit_count = 0
        self.commit_count = 0
        self.rollback_count = 0

        self.exited = False

        self.exit_exception_type: (
            type[BaseException] | None
        ) = None

    def __enter__(
        self,
    ) -> FakeUnitOfWork:
        self.enter_count += 1
        self.exited = False
        self.exit_exception_type = None

        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_value
        del traceback

        self.exit_count += 1
        self.exited = True
        self.exit_exception_type = exc_type

    def commit(
        self,
    ) -> None:
        self.commit_count += 1

    def rollback(
        self,
    ) -> None:
        self.rollback_count += 1


def _snapshot(
    *,
    score: float = 0.99999,
    percentile: float = 1.0,
    score_date: date = date(
        2026,
        7,
        30,
    ),
) -> EPSSSnapshot:
    return EPSSSnapshot(
        score=score,
        percentile=percentile,
        score_date=score_date,
    )


def _build_service(
    *,
    repository_result: object | None = None,
    repository_error: Exception | None = None,
    max_cve_ids: int = 50_000,
) -> tuple[
    EPSSLookupService,
    FakeUnitOfWork,
    FakeEPSSRepository,
]:
    repository = FakeEPSSRepository(
        result=repository_result,
        error=repository_error,
    )

    unit_of_work = FakeUnitOfWork(
        repository
    )

    service = EPSSLookupService(
        unit_of_work=unit_of_work,  # type: ignore[arg-type]
        max_cve_ids=max_cve_ids,
    )

    return (
        service,
        unit_of_work,
        repository,
    )


def test_constructor_rejects_missing_unit_of_work(
) -> None:
    with pytest.raises(
        ValueError,
        match="unit_of_work must not be None",
    ):
        EPSSLookupService(
            unit_of_work=None,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "invalid_limit",
    [
        True,
        1.5,
        "100",
        None,
    ],
)
def test_constructor_rejects_invalid_limit_type(
    invalid_limit: object,
) -> None:
    repository = FakeEPSSRepository()

    unit_of_work = FakeUnitOfWork(
        repository
    )

    with pytest.raises(
        TypeError,
        match=(
            "max_cve_ids must be an integer"
        ),
    ):
        EPSSLookupService(
            unit_of_work=unit_of_work,  # type: ignore[arg-type]
            max_cve_ids=invalid_limit,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "invalid_limit",
    [
        0,
        -1,
    ],
)
def test_constructor_rejects_non_positive_limit(
    invalid_limit: int,
) -> None:
    repository = FakeEPSSRepository()

    unit_of_work = FakeUnitOfWork(
        repository
    )

    with pytest.raises(
        ValueError,
        match=(
            "max_cve_ids must be "
            "greater than zero"
        ),
    ):
        EPSSLookupService(
            unit_of_work=unit_of_work,  # type: ignore[arg-type]
            max_cve_ids=invalid_limit,
        )


def test_find_many_returns_empty_without_transaction(
) -> None:
    service, unit_of_work, repository = (
        _build_service()
    )

    result = service.find_many_by_cve_ids(
        [
            None,
            "",
            "INVALID",
            "GHSA-xxxx-yyyy-zzzz",
        ]
    )

    assert result == {}
    assert repository.calls == []

    assert unit_of_work.enter_count == 0
    assert unit_of_work.exit_count == 0
    assert unit_of_work.commit_count == 0
    assert unit_of_work.rollback_count == 0


def test_find_many_normalizes_and_deduplicates_cves(
) -> None:
    snapshot = _snapshot()

    service, unit_of_work, repository = (
        _build_service(
            repository_result={
                "CVE-2021-44228": snapshot,
            },
        )
    )

    result = service.find_many_by_cve_ids(
        [
            " cve-2021-44228 ",
            "CVE-2021-44228",
            None,
            123,  # type: ignore[list-item]
            "INVALID",
        ]
    )

    assert result == {
        "CVE-2021-44228": snapshot,
    }

    assert repository.calls == [
        [
            "CVE-2021-44228",
        ]
    ]

    assert unit_of_work.enter_count == 1
    assert unit_of_work.exit_count == 1
    assert unit_of_work.exited is True

    assert (
        unit_of_work.exit_exception_type
        is None
    )

    assert unit_of_work.commit_count == 0
    assert unit_of_work.rollback_count == 0


def test_find_many_preserves_requested_order(
) -> None:
    first_snapshot = _snapshot(
        score=0.91,
    )

    second_snapshot = _snapshot(
        score=0.82,
    )

    service, _, repository = (
        _build_service(
            repository_result={
                "CVE-2024-3094": second_snapshot,
                "CVE-2021-44228": first_snapshot,
            },
        )
    )

    result = service.find_many_by_cve_ids(
        [
            "CVE-2021-44228",
            "CVE-2024-3094",
        ]
    )

    assert list(result) == [
        "CVE-2021-44228",
        "CVE-2024-3094",
    ]

    assert repository.calls == [
        [
            "CVE-2021-44228",
            "CVE-2024-3094",
        ]
    ]


def test_find_many_omits_missing_cves(
) -> None:
    snapshot = _snapshot()

    service, _, repository = (
        _build_service(
            repository_result={
                "CVE-2021-44228": snapshot,
            },
        )
    )

    result = service.find_many_by_cve_ids(
        [
            "CVE-2021-44228",
            "CVE-2099-0001",
        ]
    )

    assert result == {
        "CVE-2021-44228": snapshot,
    }

    assert repository.calls == [
        [
            "CVE-2021-44228",
            "CVE-2099-0001",
        ]
    ]


def test_find_many_accepts_generator(
) -> None:
    snapshot = _snapshot()

    service, _, repository = (
        _build_service(
            repository_result={
                "CVE-2021-44228": snapshot,
            },
        )
    )

    cve_ids = (
        value
        for value in [
            "cve-2021-44228",
            "CVE-2021-44228",
        ]
    )

    result = service.find_many_by_cve_ids(
        cve_ids
    )

    assert result == {
        "CVE-2021-44228": snapshot,
    }

    assert repository.calls == [
        [
            "CVE-2021-44228",
        ]
    ]


def test_find_many_rejects_string_collection(
) -> None:
    service, unit_of_work, repository = (
        _build_service()
    )

    with pytest.raises(
        TypeError,
        match=(
            "cve_ids must be an iterable "
            "of identifiers"
        ),
    ):
        service.find_many_by_cve_ids(
            "CVE-2021-44228"  # type: ignore[arg-type]
        )

    assert repository.calls == []
    assert unit_of_work.enter_count == 0


def test_find_many_rejects_non_iterable_collection(
) -> None:
    service, unit_of_work, repository = (
        _build_service()
    )

    with pytest.raises(
        TypeError,
        match="cve_ids must be iterable",
    ):
        service.find_many_by_cve_ids(
            123  # type: ignore[arg-type]
        )

    assert repository.calls == []
    assert unit_of_work.enter_count == 0


def test_find_many_enforces_configured_limit(
) -> None:
    service, unit_of_work, repository = (
        _build_service(
            max_cve_ids=1,
        )
    )

    with pytest.raises(
        ValueError,
        match=(
            "cve_ids exceeds the configured "
            "limit of 1"
        ),
    ):
        service.find_many_by_cve_ids(
            [
                "CVE-2021-44228",
                "CVE-2024-3094",
            ]
        )

    assert repository.calls == []
    assert unit_of_work.enter_count == 0


def test_find_many_rejects_non_mapping_repository_result(
) -> None:
    service, unit_of_work, repository = (
        _build_service(
            repository_result=[
                _snapshot(),
            ],
        )
    )

    with pytest.raises(
        TypeError,
        match=(
            "epss repository result "
            "must be a mapping"
        ),
    ):
        service.find_many_by_cve_ids(
            [
                "CVE-2021-44228",
            ]
        )

    assert repository.calls == [
        [
            "CVE-2021-44228",
        ]
    ]

    assert unit_of_work.exited is True

    # La validation est volontairement réalisée
    # après la fermeture de la transaction.
    assert (
        unit_of_work.exit_exception_type
        is None
    )


def test_find_many_rejects_unexpected_repository_cve(
) -> None:
    service, unit_of_work, _ = (
        _build_service(
            repository_result={
                "CVE-2024-3094": _snapshot(),
            },
        )
    )

    with pytest.raises(
        RuntimeError,
        match=(
            "epss repository returned "
            "unexpected CVE identifiers"
        ),
    ):
        service.find_many_by_cve_ids(
            [
                "CVE-2021-44228",
            ]
        )

    assert unit_of_work.exited is True

    assert (
        unit_of_work.exit_exception_type
        is None
    )


def test_find_many_rejects_invalid_repository_value(
) -> None:
    service, unit_of_work, _ = (
        _build_service(
            repository_result={
                "CVE-2021-44228": {
                    "score": 0.99,
                },
            },
        )
    )

    with pytest.raises(
        TypeError,
        match=(
            "epss repository values must "
            "be EPSSSnapshot instances"
        ),
    ):
        service.find_many_by_cve_ids(
            [
                "CVE-2021-44228",
            ]
        )

    assert unit_of_work.exited is True

    assert (
        unit_of_work.exit_exception_type
        is None
    )


def test_repository_failure_closes_transaction(
) -> None:
    expected_error = RuntimeError(
        "PostgreSQL read failure"
    )

    service, unit_of_work, repository = (
        _build_service(
            repository_error=expected_error,
        )
    )

    with pytest.raises(
        RuntimeError,
        match="PostgreSQL read failure",
    ) as raised_error:
        service.find_many_by_cve_ids(
            [
                "CVE-2021-44228",
            ]
        )

    assert raised_error.value is expected_error

    assert repository.calls == [
        [
            "CVE-2021-44228",
        ]
    ]

    assert unit_of_work.enter_count == 1
    assert unit_of_work.exit_count == 1
    assert unit_of_work.exited is True

    assert (
        unit_of_work.exit_exception_type
        is RuntimeError
    )

    assert unit_of_work.commit_count == 0
    assert unit_of_work.rollback_count == 0