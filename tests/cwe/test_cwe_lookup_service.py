from __future__ import annotations

from types import TracebackType
from typing import Any

import pytest

from application.services.cwe_lookup_service import (
    CWELookupService,
)
from domain.cwe_weakness import CWEWeakness


class FakeCWERepository:
    """
    Repository CWE déterministe sans accès PostgreSQL.

    Le résultat reste volontairement typé comme object
    afin de simuler un adaptateur défectueux.
    """

    def __init__(
        self,
        *,
        result: object | None = None,
        error: Exception | None = None,
    ) -> None:
        self.result = (
            []
            if result is None
            else result
        )
        self.error = error

        self.calls: list[
            list[str]
        ] = []

    def find_many_by_ids(
        self,
        cwe_ids: list[str],
    ) -> object:
        self.calls.append(
            list(cwe_ids)
        )

        if self.error is not None:
            raise self.error

        return self.result


class FakeUnitOfWork:
    """
    Unit of Work déterministe limité au lookup CWE.
    """

    def __init__(
        self,
        repository: FakeCWERepository,
    ) -> None:
        self.cwe_weaknesses: Any = repository

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


def _weakness(
    *,
    cwe_id: str = "CWE-79",
    name: str = "Cross-site Scripting",
) -> CWEWeakness:
    return CWEWeakness(
        id=cwe_id,
        name=name,
        description="Official CWE description.",
    )


def _build_service(
    *,
    repository_result: object | None = None,
    repository_error: Exception | None = None,
    max_cwe_ids: int = 10_000,
) -> tuple[
    CWELookupService,
    FakeUnitOfWork,
    FakeCWERepository,
]:
    repository = FakeCWERepository(
        result=repository_result,
        error=repository_error,
    )

    unit_of_work = FakeUnitOfWork(
        repository
    )

    service = CWELookupService(
        unit_of_work=unit_of_work,  # type: ignore[arg-type]
        max_cwe_ids=max_cwe_ids,
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
        CWELookupService(
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
    repository = FakeCWERepository()

    unit_of_work = FakeUnitOfWork(
        repository
    )

    with pytest.raises(
        TypeError,
        match="max_cwe_ids must be an integer",
    ):
        CWELookupService(
            unit_of_work=unit_of_work,  # type: ignore[arg-type]
            max_cwe_ids=invalid_limit,  # type: ignore[arg-type]
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
    repository = FakeCWERepository()

    unit_of_work = FakeUnitOfWork(
        repository
    )

    with pytest.raises(
        ValueError,
        match=(
            "max_cwe_ids must be "
            "greater than zero"
        ),
    ):
        CWELookupService(
            unit_of_work=unit_of_work,  # type: ignore[arg-type]
            max_cwe_ids=invalid_limit,
        )


def test_find_many_returns_empty_without_transaction(
) -> None:
    service, unit_of_work, repository = (
        _build_service()
    )

    result = service.find_many_by_cwe_ids(
        [
            None,
            "",
            "INVALID",
            "CWE-0",
            "CWE-" + ("9" * 40),
            79,  # type: ignore[list-item]
        ]
    )

    assert result == {}
    assert repository.calls == []

    assert unit_of_work.enter_count == 0
    assert unit_of_work.exit_count == 0
    assert unit_of_work.commit_count == 0
    assert unit_of_work.rollback_count == 0


def test_find_many_normalizes_and_deduplicates_ids(
) -> None:
    weakness = _weakness()

    service, unit_of_work, repository = (
        _build_service(
            repository_result=[
                weakness,
            ],
        )
    )

    result = service.find_many_by_cwe_ids(
        [
            " cwe-00079 ",
            "CWE-79",
            "79",
            None,
            "INVALID",
        ]
    )

    assert result == {
        "CWE-79": weakness,
    }

    assert repository.calls == [
        [
            "CWE-79",
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


def test_find_many_preserves_order_and_omits_missing_ids(
) -> None:
    first_weakness = _weakness(
        cwe_id="CWE-79",
    )

    second_weakness = _weakness(
        cwe_id="CWE-89",
        name="SQL Injection",
    )

    service, _, repository = (
        _build_service(
            repository_result=[
                second_weakness,
                first_weakness,
            ],
        )
    )

    result = service.find_many_by_cwe_ids(
        [
            "CWE-79",
            "CWE-999999",
            "CWE-89",
        ]
    )

    assert list(result) == [
        "CWE-79",
        "CWE-89",
    ]

    assert result == {
        "CWE-79": first_weakness,
        "CWE-89": second_weakness,
    }

    assert repository.calls == [
        [
            "CWE-79",
            "CWE-999999",
            "CWE-89",
        ]
    ]


def test_find_many_accepts_generator(
) -> None:
    weakness = _weakness()

    service, _, repository = (
        _build_service(
            repository_result=[
                weakness,
            ],
        )
    )

    cwe_ids = (
        value
        for value in [
            "cwe-79",
            "CWE-00079",
        ]
    )

    result = service.find_many_by_cwe_ids(
        cwe_ids
    )

    assert result == {
        "CWE-79": weakness,
    }

    assert repository.calls == [
        [
            "CWE-79",
        ]
    ]


@pytest.mark.parametrize(
    (
        "invalid_collection",
        "expected_message",
    ),
    [
        (
            "CWE-79",
            (
                "cwe_ids must be an iterable "
                "of identifiers"
            ),
        ),
        (
            123,
            "cwe_ids must be iterable",
        ),
    ],
)
def test_find_many_rejects_invalid_collection(
    invalid_collection: object,
    expected_message: str,
) -> None:
    service, unit_of_work, repository = (
        _build_service()
    )

    with pytest.raises(
        TypeError,
        match=expected_message,
    ):
        service.find_many_by_cwe_ids(
            invalid_collection  # type: ignore[arg-type]
        )

    assert repository.calls == []
    assert unit_of_work.enter_count == 0


def test_find_many_enforces_configured_limit(
) -> None:
    service, unit_of_work, repository = (
        _build_service(
            max_cwe_ids=1,
        )
    )

    with pytest.raises(
        ValueError,
        match=(
            "cwe_ids exceeds the configured "
            "limit of 1"
        ),
    ):
        service.find_many_by_cwe_ids(
            [
                "CWE-79",
                "CWE-89",
            ]
        )

    assert repository.calls == []
    assert unit_of_work.enter_count == 0


def test_find_many_rejects_non_list_repository_result(
) -> None:
    service, unit_of_work, repository = (
        _build_service(
            repository_result={
                "CWE-79": _weakness(),
            },
        )
    )

    with pytest.raises(
        TypeError,
        match=(
            "cwe repository result "
            "must be a list"
        ),
    ):
        service.find_many_by_cwe_ids(
            [
                "CWE-79",
            ]
        )

    assert repository.calls == [
        [
            "CWE-79",
        ]
    ]

    assert unit_of_work.exited is True

    # La validation du résultat est volontairement
    # effectuée après la fermeture de la transaction.
    assert (
        unit_of_work.exit_exception_type
        is None
    )


def test_find_many_rejects_invalid_repository_value(
) -> None:
    service, unit_of_work, _ = (
        _build_service(
            repository_result=[
                {
                    "id": "CWE-79",
                },
            ],
        )
    )

    with pytest.raises(
        TypeError,
        match=(
            "cwe repository values must "
            "be CWEWeakness instances"
        ),
    ):
        service.find_many_by_cwe_ids(
            [
                "CWE-79",
            ]
        )

    assert unit_of_work.exited is True

    assert (
        unit_of_work.exit_exception_type
        is None
    )


@pytest.mark.parametrize(
    (
        "repository_result",
        "expected_exception",
        "expected_message",
    ),
    [
        (
            [
                _weakness(
                    cwe_id="INVALID",
                ),
            ],
            TypeError,
            (
                "cwe repository returned "
                "an invalid CWE identifier"
            ),
        ),
        (
            [
                _weakness(
                    cwe_id="cwe-00079",
                ),
            ],
            RuntimeError,
            (
                "cwe repository returned "
                "a non-normalized CWE identifier"
            ),
        ),
        (
            [
                _weakness(
                    cwe_id="CWE-89",
                ),
            ],
            RuntimeError,
            (
                "cwe repository returned "
                "unexpected CWE identifiers"
            ),
        ),
        (
            [
                _weakness(),
                _weakness(),
            ],
            RuntimeError,
            (
                "cwe repository returned "
                "duplicate CWE identifiers"
            ),
        ),
    ],
)
def test_find_many_rejects_invalid_repository_ids(
    repository_result: list[CWEWeakness],
    expected_exception: type[Exception],
    expected_message: str,
) -> None:
    service, unit_of_work, _ = (
        _build_service(
            repository_result=repository_result,
        )
    )

    with pytest.raises(
        expected_exception,
        match=expected_message,
    ):
        service.find_many_by_cwe_ids(
            [
                "CWE-79",
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
        service.find_many_by_cwe_ids(
            [
                "CWE-79",
            ]
        )

    assert raised_error.value is expected_error

    assert repository.calls == [
        [
            "CWE-79",
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