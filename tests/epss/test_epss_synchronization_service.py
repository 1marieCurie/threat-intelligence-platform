from __future__ import annotations

from collections.abc import (
    Iterable,
    Mapping,
)
from datetime import date, datetime
from types import TracebackType
from typing import Any, cast

import pytest

from application.models.epss_snapshot import (
    EPSSSnapshot,
)
from application.ports.outbound.epss_provider import (
    EPSSProvider,
    EPSSProviderUnavailableError,
)
from application.ports.outbound.unit_of_work import (
    UnitOfWork,
)
from application.services.epss_synchronization_service import (
    EPSSSynchronizationService,
)


class FakeEPSSProvider(EPSSProvider):
    def __init__(
        self,
        *,
        result: Mapping[
            str,
            EPSSSnapshot,
        ] | object | None = None,
        error: Exception | None = None,
        events: list[str] | None = None,
    ) -> None:
        self.result = (
            {}
            if result is None
            else result
        )
        self.error = error
        self.events = (
            events
            if events is not None
            else []
        )

        self.calls: list[
            tuple[
                tuple[str, ...],
                date | None,
            ]
        ] = []

    def fetch_by_cve_ids(
        self,
        cve_ids: Iterable[str],
        *,
        score_date: date | None = None,
    ) -> Mapping[str, EPSSSnapshot]:
        normalized_values = tuple(
            cve_ids
        )

        self.calls.append(
            (
                normalized_values,
                score_date,
            )
        )

        self.events.append(
            "provider.fetch"
        )

        if self.error is not None:
            raise self.error

        return cast(
            Mapping[
                str,
                EPSSSnapshot,
            ],
            self.result,
        )


class FakeEPSSRepository:
    def __init__(
        self,
        *,
        returned_count: int | None = None,
        error: Exception | None = None,
        events: list[str] | None = None,
    ) -> None:
        self.returned_count = returned_count
        self.error = error
        self.events = (
            events
            if events is not None
            else []
        )

        self.calls: list[
            dict[
                str,
                EPSSSnapshot,
            ]
        ] = []

    def upsert_many(
        self,
        snapshots_by_cve: Mapping[
            str,
            EPSSSnapshot,
        ],
    ) -> int:
        self.events.append(
            "repository.upsert"
        )

        if self.error is not None:
            raise self.error

        copied_values = dict(
            snapshots_by_cve
        )

        self.calls.append(
            copied_values
        )

        if self.returned_count is not None:
            return self.returned_count

        return len(
            copied_values
        )


class FakeUnitOfWork:
    def __init__(
        self,
        *,
        repository: FakeEPSSRepository,
        events: list[str] | None = None,
    ) -> None:
        self.epss_scores = repository

        self.events = (
            events
            if events is not None
            else []
        )

        self.enter_count = 0
        self.exit_count = 0
        self.commit_count = 0
        self.rollback_count = 0

    def __enter__(
        self,
    ) -> FakeUnitOfWork:
        self.enter_count += 1

        self.events.append(
            "uow.enter"
        )

        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.exit_count += 1

        if exc_type is not None:
            self.rollback()

        self.events.append(
            "uow.exit"
        )

    def commit(self) -> None:
        self.commit_count += 1

        self.events.append(
            "uow.commit"
        )

    def rollback(self) -> None:
        self.rollback_count += 1

        self.events.append(
            "uow.rollback"
        )


def _build_snapshot(
    *,
    score: float = 0.85,
    percentile: float = 0.97,
    score_date: date = date(
        2026,
        7,
        30,
    ),
    api_version: str | None = "2026.07",
) -> EPSSSnapshot:
    return EPSSSnapshot(
        score=score,
        percentile=percentile,
        score_date=score_date,
        api_version=api_version,
    )


def _build_service(
    *,
    provider_result: (
        Mapping[str, EPSSSnapshot]
        | object
        | None
    ) = None,
    provider_error: Exception | None = None,
    repository_error: Exception | None = None,
    returned_count: int | None = None,
    max_cve_ids: int = 50_000,
) -> tuple[
    EPSSSynchronizationService,
    FakeEPSSProvider,
    FakeUnitOfWork,
    FakeEPSSRepository,
    list[str],
]:
    events: list[str] = []

    provider = FakeEPSSProvider(
        result=provider_result,
        error=provider_error,
        events=events,
    )

    repository = FakeEPSSRepository(
        returned_count=returned_count,
        error=repository_error,
        events=events,
    )

    unit_of_work = FakeUnitOfWork(
        repository=repository,
        events=events,
    )

    service = EPSSSynchronizationService(
        provider=provider,
        unit_of_work=cast(
            UnitOfWork,
            unit_of_work,
        ),
        max_cve_ids=max_cve_ids,
    )

    return (
        service,
        provider,
        unit_of_work,
        repository,
        events,
    )


def test_constructor_rejects_missing_provider() -> None:
    repository = FakeEPSSRepository()

    unit_of_work = FakeUnitOfWork(
        repository=repository,
    )

    with pytest.raises(
        ValueError,
        match="provider is required",
    ):
        EPSSSynchronizationService(
            provider=None,  # type: ignore[arg-type]
            unit_of_work=cast(
                UnitOfWork,
                unit_of_work,
            ),
        )


def test_constructor_rejects_missing_unit_of_work(
) -> None:
    provider = FakeEPSSProvider()

    with pytest.raises(
        ValueError,
        match="unit_of_work is required",
    ):
        EPSSSynchronizationService(
            provider=provider,
            unit_of_work=None,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "invalid_value",
    [
        True,
        1.5,
        "100",
        None,
    ],
)
def test_constructor_rejects_invalid_limit_type(
    invalid_value: object,
) -> None:
    provider = FakeEPSSProvider()

    repository = FakeEPSSRepository()

    unit_of_work = FakeUnitOfWork(
        repository=repository,
    )

    with pytest.raises(
        TypeError,
        match=(
            "max_cve_ids must be "
            "an integer"
        ),
    ):
        EPSSSynchronizationService(
            provider=provider,
            unit_of_work=cast(
                UnitOfWork,
                unit_of_work,
            ),
            max_cve_ids=invalid_value,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "invalid_value",
    [
        0,
        -1,
    ],
)
def test_constructor_rejects_non_positive_limit(
    invalid_value: int,
) -> None:
    provider = FakeEPSSProvider()

    repository = FakeEPSSRepository()

    unit_of_work = FakeUnitOfWork(
        repository=repository,
    )

    with pytest.raises(
        ValueError,
        match=(
            "max_cve_ids must be "
            "greater than zero"
        ),
    ):
        EPSSSynchronizationService(
            provider=provider,
            unit_of_work=cast(
                UnitOfWork,
                unit_of_work,
            ),
            max_cve_ids=invalid_value,
        )


def test_synchronize_returns_empty_without_external_calls(
) -> None:
    (
        service,
        provider,
        unit_of_work,
        repository,
        events,
    ) = _build_service()

    result = service.synchronize(
        []
    )

    assert result.requested_cves == 0
    assert result.fetched_scores == 0
    assert result.submitted_scores == 0
    assert result.missing_cves == ()
    assert result.requested_score_date is None

    assert provider.calls == []
    assert repository.calls == []

    assert unit_of_work.enter_count == 0
    assert unit_of_work.commit_count == 0

    assert events == []


def test_synchronize_normalizes_and_deduplicates_cves(
) -> None:
    first_snapshot = _build_snapshot(
        score=0.95,
    )

    second_snapshot = _build_snapshot(
        score=0.80,
    )

    (
        service,
        provider,
        unit_of_work,
        repository,
        _,
    ) = _build_service(
        provider_result={
            "CVE-2021-44228": first_snapshot,
            "CVE-2024-4577": second_snapshot,
        }
    )

    result = service.synchronize(
        [
            " cve-2021-44228 ",
            "CVE-2024-4577",
            "CVE-2021-44228",
        ]
    )

    assert provider.calls == [
        (
            (
                "CVE-2021-44228",
                "CVE-2024-4577",
            ),
            None,
        ),
    ]

    assert repository.calls == [
        {
            "CVE-2021-44228": first_snapshot,
            "CVE-2024-4577": second_snapshot,
        }
    ]

    assert result.requested_cves == 2
    assert result.fetched_scores == 2
    assert result.submitted_scores == 2
    assert result.missing_cves == ()

    assert unit_of_work.commit_count == 1


def test_synchronize_reports_missing_cves() -> None:
    snapshot = _build_snapshot()

    (
        service,
        _,
        unit_of_work,
        repository,
        _,
    ) = _build_service(
        provider_result={
            "CVE-2021-44228": snapshot,
        }
    )

    result = service.synchronize(
        [
            "CVE-2021-44228",
            "CVE-2024-4577",
            "CVE-2019-19781",
        ]
    )

    assert result.requested_cves == 3
    assert result.fetched_scores == 1
    assert result.submitted_scores == 1

    assert result.missing_cves == (
        "CVE-2024-4577",
        "CVE-2019-19781",
    )

    assert repository.calls == [
        {
            "CVE-2021-44228": snapshot,
        }
    ]

    assert unit_of_work.commit_count == 1


def test_synchronize_does_not_open_transaction_when_no_scores_found(
) -> None:
    (
        service,
        provider,
        unit_of_work,
        repository,
        events,
    ) = _build_service(
        provider_result={}
    )

    result = service.synchronize(
        [
            "CVE-2021-44228",
            "CVE-2024-4577",
        ]
    )

    assert result.requested_cves == 2
    assert result.fetched_scores == 0
    assert result.submitted_scores == 0

    assert result.missing_cves == (
        "CVE-2021-44228",
        "CVE-2024-4577",
    )

    assert len(provider.calls) == 1
    assert repository.calls == []

    assert unit_of_work.enter_count == 0
    assert unit_of_work.commit_count == 0

    assert events == [
        "provider.fetch",
    ]


def test_provider_call_occurs_before_transaction(
) -> None:
    snapshot = _build_snapshot()

    (
        service,
        _,
        _,
        _,
        events,
    ) = _build_service(
        provider_result={
            "CVE-2021-44228": snapshot,
        }
    )

    service.synchronize(
        [
            "CVE-2021-44228",
        ]
    )

    assert events == [
        "provider.fetch",
        "uow.enter",
        "repository.upsert",
        "uow.commit",
        "uow.exit",
    ]


def test_provider_failure_does_not_open_transaction(
) -> None:
    provider_error = (
        EPSSProviderUnavailableError(
            "FIRST unavailable"
        )
    )

    (
        service,
        _,
        unit_of_work,
        repository,
        events,
    ) = _build_service(
        provider_error=provider_error
    )

    with pytest.raises(
        EPSSProviderUnavailableError,
        match="FIRST unavailable",
    ):
        service.synchronize(
            [
                "CVE-2021-44228",
            ]
        )

    assert repository.calls == []

    assert unit_of_work.enter_count == 0
    assert unit_of_work.commit_count == 0
    assert unit_of_work.rollback_count == 0

    assert events == [
        "provider.fetch",
    ]


def test_repository_failure_does_not_commit(
) -> None:
    snapshot = _build_snapshot()

    (
        service,
        _,
        unit_of_work,
        _,
        events,
    ) = _build_service(
        provider_result={
            "CVE-2021-44228": snapshot,
        },
        repository_error=RuntimeError(
            "database failure"
        ),
    )

    with pytest.raises(
        RuntimeError,
        match="database failure",
    ):
        service.synchronize(
            [
                "CVE-2021-44228",
            ]
        )

    assert unit_of_work.commit_count == 0
    assert unit_of_work.rollback_count == 1

    assert events == [
        "provider.fetch",
        "uow.enter",
        "repository.upsert",
        "uow.rollback",
        "uow.exit",
    ]


def test_synchronize_uses_repository_returned_count(
) -> None:
    snapshot = _build_snapshot()

    (
        service,
        _,
        _,
        _,
        _,
    ) = _build_service(
        provider_result={
            "CVE-2021-44228": snapshot,
        },
        returned_count=0,
    )

    result = service.synchronize(
        [
            "CVE-2021-44228",
        ]
    )

    assert result.fetched_scores == 1
    assert result.submitted_scores == 0


def test_synchronize_passes_historical_date_to_provider(
) -> None:
    requested_date = date(
        2026,
        7,
        29,
    )

    snapshot = _build_snapshot(
        score_date=requested_date,
    )

    (
        service,
        provider,
        _,
        _,
        _,
    ) = _build_service(
        provider_result={
            "CVE-2021-44228": snapshot,
        }
    )

    result = service.synchronize(
        [
            "CVE-2021-44228",
        ],
        score_date=requested_date,
    )

    assert provider.calls == [
        (
            (
                "CVE-2021-44228",
            ),
            requested_date,
        ),
    ]

    assert (
        result.requested_score_date
        == requested_date
    )


def test_synchronize_rejects_string_collection(
) -> None:
    (
        service,
        provider,
        unit_of_work,
        _,
        _,
    ) = _build_service()

    with pytest.raises(
        TypeError,
        match=(
            "cve_ids must be an iterable "
            "of strings"
        ),
    ):
        service.synchronize(
            "CVE-2021-44228"
        )

    assert provider.calls == []
    assert unit_of_work.enter_count == 0


def test_synchronize_rejects_non_iterable_collection(
) -> None:
    (
        service,
        provider,
        unit_of_work,
        _,
        _,
    ) = _build_service()

    with pytest.raises(
        TypeError,
        match=(
            "cve_ids must be an iterable "
            "of strings"
        ),
    ):
        service.synchronize(
            1234  # type: ignore[arg-type]
        )

    assert provider.calls == []
    assert unit_of_work.enter_count == 0


def test_synchronize_rejects_non_string_identifier(
) -> None:
    (
        service,
        provider,
        unit_of_work,
        _,
        _,
    ) = _build_service()

    with pytest.raises(
        TypeError,
        match=(
            "Every CVE identifier must "
            "be a string"
        ),
    ):
        service.synchronize(
            [
                "CVE-2021-44228",
                None,  # type: ignore[list-item]
            ]
        )

    assert provider.calls == []
    assert unit_of_work.enter_count == 0


@pytest.mark.parametrize(
    "invalid_cve_id",
    [
        "",
        "CVE-2026-123",
        "CVE-26-1234",
        "CWE-79",
        "invalid",
    ],
)
def test_synchronize_rejects_invalid_identifier(
    invalid_cve_id: str,
) -> None:
    (
        service,
        provider,
        unit_of_work,
        _,
        _,
    ) = _build_service()

    with pytest.raises(
        ValueError,
        match=(
            "Every value must be a valid "
            "CVE identifier"
        ),
    ):
        service.synchronize(
            [
                invalid_cve_id,
            ]
        )

    assert provider.calls == []
    assert unit_of_work.enter_count == 0


def test_synchronize_enforces_cve_limit() -> None:
    (
        service,
        provider,
        unit_of_work,
        _,
        _,
    ) = _build_service(
        max_cve_ids=2
    )

    with pytest.raises(
        RuntimeError,
        match=(
            "EPSS CVE identifier limit "
            "was exceeded"
        ),
    ):
        service.synchronize(
            [
                "CVE-2026-1001",
                "CVE-2026-1002",
                "CVE-2026-1003",
            ]
        )

    assert provider.calls == []
    assert unit_of_work.enter_count == 0


@pytest.mark.parametrize(
    "invalid_date",
    [
        "2026-07-30",
        datetime(
            2026,
            7,
            30,
        ),
    ],
)
def test_synchronize_validates_score_date_type(
    invalid_date: object,
) -> None:

    (
        service,
        provider,
        unit_of_work,
        _,
        _,
    ) = _build_service()

    with pytest.raises(
        TypeError,
        match=(
            "score_date must be a date "
            "or None"
        ),
    ):
        service.synchronize(
            [
                "CVE-2021-44228",
            ],
            score_date=invalid_date,  # type: ignore[arg-type]
        )

    assert provider.calls == []
    assert unit_of_work.enter_count == 0


def test_synchronize_rejects_non_mapping_provider_result(
) -> None:
    (
        service,
        _,
        unit_of_work,
        _,
        _,
    ) = _build_service(
        provider_result=[]
    )

    with pytest.raises(
        TypeError,
        match=(
            "EPSS provider result must "
            "be a mapping"
        ),
    ):
        service.synchronize(
            [
                "CVE-2021-44228",
            ]
        )

    assert unit_of_work.enter_count == 0


def test_synchronize_rejects_unexpected_provider_cve(
) -> None:
    (
        service,
        _,
        unit_of_work,
        _,
        _,
    ) = _build_service(
        provider_result={
            "CVE-2024-4577": (
                _build_snapshot()
            ),
        }
    )

    with pytest.raises(
        ValueError,
        match=(
            "unexpected CVE identifier"
        ),
    ):
        service.synchronize(
            [
                "CVE-2021-44228",
            ]
        )

    assert unit_of_work.enter_count == 0


def test_synchronize_rejects_non_normalized_provider_key(
) -> None:
    (
        service,
        _,
        unit_of_work,
        _,
        _,
    ) = _build_service(
        provider_result={
            "cve-2021-44228": (
                _build_snapshot()
            ),
        }
    )

    with pytest.raises(
        ValueError,
        match=(
            "non-normalized CVE identifier"
        ),
    ):
        service.synchronize(
            [
                "CVE-2021-44228",
            ]
        )

    assert unit_of_work.enter_count == 0


def test_synchronize_rejects_invalid_provider_value(
) -> None:
    (
        service,
        _,
        unit_of_work,
        _,
        _,
    ) = _build_service(
        provider_result={
            "CVE-2021-44228": {
                "score": 0.85,
            },
        }
    )

    with pytest.raises(
        TypeError,
        match=(
            "EPSS provider values must "
            "be EPSSSnapshot instances"
        ),
    ):
        service.synchronize(
            [
                "CVE-2021-44228",
            ]
        )

    assert unit_of_work.enter_count == 0
    
def test_synchronize_rejects_mismatched_historical_date(
) -> None:
    requested_date = date(
        2026,
        7,
        29,
    )

    provider_snapshot = _build_snapshot(
        score_date=date(
            2026,
            7,
            30,
        ),
    )

    (
        service,
        provider,
        unit_of_work,
        repository,
        events,
    ) = _build_service(
        provider_result={
            "CVE-2021-44228": (
                provider_snapshot
            ),
        }
    )

    with pytest.raises(
        ValueError,
        match=(
            "score date that does not match "
            "the requested date"
        ),
    ):
        service.synchronize(
            [
                "CVE-2021-44228",
            ],
            score_date=requested_date,
        )

    assert provider.calls == [
        (
            (
                "CVE-2021-44228",
            ),
            requested_date,
        ),
    ]

    assert repository.calls == []
    assert unit_of_work.enter_count == 0
    assert unit_of_work.commit_count == 0

    assert events == [
        "provider.fetch",
    ]