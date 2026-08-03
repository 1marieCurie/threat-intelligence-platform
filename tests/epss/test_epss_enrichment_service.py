from __future__ import annotations

from collections.abc import Mapping
from datetime import date
from types import TracebackType
from typing import Any
from unittest.mock import Mock

import pytest

from application.models.epss_snapshot import (
    EPSSSnapshot,
)
from application.services.epss_enrichment_service import (
    EPSSEnrichmentResult,
    EPSSEnrichmentService,
)
from domain.threat import Threat
from domain.threat_category import ThreatCategory


class FakeEPSSRepository:
    """
    Repository EPSS déterministe sans accès PostgreSQL.

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
    Unit of Work déterministe utilisé par les tests.

    Seul epss_scores fournit un comportement réel.
    Les autres repositories sont des mocks car ils ne
    participent pas au cas d'usage testé.
    """

    def __init__(
        self,
        repository: FakeEPSSRepository,
    ) -> None:
        self.ingestion_runs: Any = Mock()
        self.raw_payloads: Any = Mock()
        self.ingestion_run_payloads: Any = Mock()
        self.sync_states: Any = Mock()

        self.cisa_kev_vulnerabilities: Any = (
            Mock()
        )

        self.github_advisory_vulnerabilities: Any = (
            Mock()
        )

        self.cwe_weaknesses: Any = Mock()

        self.vulnerability_cwe_references: Any = (
            Mock()
        )

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
    EPSSEnrichmentService,
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

    service = EPSSEnrichmentService(
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
        EPSSEnrichmentService(
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
        EPSSEnrichmentService(
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
        EPSSEnrichmentService(
            unit_of_work=unit_of_work,  # type: ignore[arg-type]
            max_cve_ids=invalid_limit,
        )


def test_fetch_returns_empty_without_transaction(
) -> None:
    service, unit_of_work, repository = (
        _build_service()
    )

    result = service.fetch_epss_by_cve_ids(
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


def test_fetch_normalizes_and_deduplicates_cves(
) -> None:
    snapshot = _snapshot()

    service, unit_of_work, repository = (
        _build_service(
            repository_result={
                "CVE-2021-44228": snapshot,
            },
        )
    )

    result = service.fetch_epss_by_cve_ids(
        [
            " cve-2021-44228 ",
            "CVE-2021-44228",
            None,
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


def test_fetch_preserves_requested_order(
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
                "CVE-2024-3094": (
                    second_snapshot
                ),
                "CVE-2021-44228": (
                    first_snapshot
                ),
            },
        )
    )

    result = service.fetch_epss_by_cve_ids(
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


def test_fetch_omits_missing_cves(
) -> None:
    snapshot = _snapshot()

    service, _, repository = (
        _build_service(
            repository_result={
                "CVE-2021-44228": snapshot,
            },
        )
    )

    result = service.fetch_epss_by_cve_ids(
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


def test_fetch_rejects_string_collection(
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
        service.fetch_epss_by_cve_ids(
            "CVE-2021-44228"  # type: ignore[arg-type]
        )

    assert repository.calls == []
    assert unit_of_work.enter_count == 0


def test_fetch_rejects_non_iterable_collection(
) -> None:
    service, unit_of_work, repository = (
        _build_service()
    )

    with pytest.raises(
        TypeError,
        match="cve_ids must be iterable",
    ):
        service.fetch_epss_by_cve_ids(
            123  # type: ignore[arg-type]
        )

    assert repository.calls == []
    assert unit_of_work.enter_count == 0


def test_fetch_enforces_configured_limit(
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
        service.fetch_epss_by_cve_ids(
            [
                "CVE-2021-44228",
                "CVE-2024-3094",
            ]
        )

    assert repository.calls == []
    assert unit_of_work.enter_count == 0


def test_fetch_rejects_historical_date_before_transaction(
) -> None:
    service, unit_of_work, repository = (
        _build_service()
    )

    with pytest.raises(
        ValueError,
        match=(
            "historical EPSS enrichment "
            "is not supported by local storage"
        ),
    ):
        service.fetch_epss_by_cve_ids(
            [
                "CVE-2021-44228",
            ],
            date="2026-07-29",
        )

    assert repository.calls == []
    assert unit_of_work.enter_count == 0


def test_fetch_rejects_non_mapping_repository_result(
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
        service.fetch_epss_by_cve_ids(
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

    # La validation du résultat est volontairement
    # effectuée après la fermeture de la transaction.
    assert (
        unit_of_work.exit_exception_type
        is None
    )


def test_fetch_rejects_unexpected_repository_cve(
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
        service.fetch_epss_by_cve_ids(
            [
                "CVE-2021-44228",
            ]
        )

    assert unit_of_work.exited is True

    assert (
        unit_of_work.exit_exception_type
        is None
    )


def test_fetch_rejects_invalid_repository_value(
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
        service.fetch_epss_by_cve_ids(
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
        service.fetch_epss_by_cve_ids(
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


def test_enriches_single_threat_from_local_snapshot(
) -> None:
    snapshot = _snapshot(
        score=0.99999,
        percentile=0.99998,
        score_date=date(
            2026,
            7,
            30,
        ),
    )

    service, unit_of_work, repository = (
        _build_service(
            repository_result={
                "CVE-2021-44228": snapshot,
            },
        )
    )

    threat = Threat(
        id="CVE-2021-44228",
        description=(
            "Apache Log4j vulnerability"
        ),
    )

    result = service.enrich_threats(
        [
            threat,
        ]
    )

    assert isinstance(
        result,
        EPSSEnrichmentResult,
    )

    assert result.threats == [
        threat,
    ]

    assert threat.epss_score == 0.99999
    assert threat.epss_percentile == 0.99998
    assert threat.epss_date == "2026-07-30"

    assert result.metadata == {
        "source": "EPSS",
        "storage": "PostgreSQL",
        "requested_cves": 1,
        "epss_records_found": 1,
        "enriched_threats": 1,
        "missing_cves": [],
        "non_cve_threats": 0,
        "date_requested": None,
    }

    assert repository.calls == [
        [
            "CVE-2021-44228",
        ]
    ]

    assert unit_of_work.exited is True
    assert unit_of_work.commit_count == 0


def test_duplicate_cves_are_loaded_once_and_all_threats_enriched(
) -> None:
    snapshot = _snapshot()

    service, _, repository = (
        _build_service(
            repository_result={
                "CVE-2021-44228": snapshot,
            },
        )
    )

    threats = [
        Threat(
            id="CVE-2021-44228",
            description="NVD record",
        ),
        Threat(
            id="cve-2021-44228",
            description="CISA record",
        ),
        Threat(
            id="GHSA-example",
            external_ids={
                "CVE": [
                    "CVE-2021-44228",
                ],
            },
            description=(
                "GitHub Advisory record"
            ),
        ),
    ]

    result = service.enrich_threats(
        threats
    )

    assert (
        result.metadata[
            "requested_cves"
        ]
        == 1
    )

    assert (
        result.metadata[
            "enriched_threats"
        ]
        == 3
    )

    for threat in threats:
        assert threat.epss_score == 0.99999
        assert threat.epss_percentile == 1.0
        assert threat.epss_date == "2026-07-30"

    assert repository.calls == [
        [
            "CVE-2021-44228",
        ]
    ]


def test_non_cve_threat_is_preserved_without_enrichment(
) -> None:
    snapshot = _snapshot()

    service, _, repository = (
        _build_service(
            repository_result={
                "CVE-2021-44228": snapshot,
            },
        )
    )

    non_cve_threat = Threat(
        id="GHSA-xxxx-yyyy-zzzz",
    )

    cve_threat = Threat(
        id="CVE-2021-44228",
    )

    result = service.enrich_threats(
        [
            non_cve_threat,
            cve_threat,
        ]
    )

    assert non_cve_threat.epss_score is None

    assert (
        non_cve_threat.epss_percentile
        is None
    )

    assert non_cve_threat.epss_date is None
    assert cve_threat.epss_score == 0.99999

    assert (
        result.metadata[
            "non_cve_threats"
        ]
        == 1
    )

    assert repository.calls == [
        [
            "CVE-2021-44228",
        ]
    ]


def test_external_cve_identifier_is_supported(
) -> None:
    snapshot = _snapshot(
        score=0.75,
    )

    service, _, repository = (
        _build_service(
            repository_result={
                "CVE-2024-3094": snapshot,
            },
        )
    )

    threat = Threat(
        id="GHSA-example",
        external_ids={
            "CVE": [
                "cve-2024-3094",
            ],
        },
    )

    result = service.enrich_threats(
        [
            threat,
        ]
    )

    assert threat.epss_score == 0.75

    assert (
        result.metadata[
            "requested_cves"
        ]
        == 1
    )

    assert repository.calls == [
        [
            "CVE-2024-3094",
        ]
    ]


def test_missing_cve_is_reported_in_metadata(
) -> None:
    snapshot = _snapshot()

    service, _, repository = (
        _build_service(
            repository_result={
                "CVE-2021-44228": snapshot,
            },
        )
    )

    known_threat = Threat(
        id="CVE-2021-44228",
    )

    missing_threat = Threat(
        id="CVE-2099-0001",
    )

    result = service.enrich_threats(
        [
            known_threat,
            missing_threat,
        ]
    )

    assert known_threat.epss_score is not None
    assert missing_threat.epss_score is None

    assert (
        result.metadata[
            "epss_records_found"
        ]
        == 1
    )

    assert (
        result.metadata[
            "enriched_threats"
        ]
        == 1
    )

    assert (
        result.metadata[
            "missing_cves"
        ]
        == [
            "CVE-2099-0001",
        ]
    )

    assert repository.calls == [
        [
            "CVE-2021-44228",
            "CVE-2099-0001",
        ]
    ]


def test_empty_threat_list_skips_transaction(
) -> None:
    service, unit_of_work, repository = (
        _build_service()
    )

    result = service.enrich_threats(
        []
    )

    assert result.threats == []

    assert result.metadata == {
        "source": "EPSS",
        "storage": "PostgreSQL",
        "requested_cves": 0,
        "epss_records_found": 0,
        "enriched_threats": 0,
        "missing_cves": [],
        "non_cve_threats": 0,
        "date_requested": None,
    }

    assert repository.calls == []
    assert unit_of_work.enter_count == 0
    assert unit_of_work.exit_count == 0


def test_enrich_threats_rejects_non_list(
) -> None:
    service, unit_of_work, repository = (
        _build_service()
    )

    with pytest.raises(
        TypeError,
        match="threats must be a list",
    ):
        service.enrich_threats(
            (  # type: ignore[arg-type]
                Threat(
                    id="CVE-2021-44228",
                ),
            )
        )

    assert repository.calls == []
    assert unit_of_work.enter_count == 0


def test_enrich_threats_rejects_invalid_element(
) -> None:
    service, unit_of_work, repository = (
        _build_service()
    )

    with pytest.raises(
        TypeError,
        match=(
            "threats must contain only "
            "Threat objects"
        ),
    ):
        service.enrich_threats(
            [
                Threat(
                    id="CVE-2021-44228",
                ),
                "invalid",  # type: ignore[list-item]
            ]
        )

    assert repository.calls == []
    assert unit_of_work.enter_count == 0


def test_enrichment_preserves_threat_category(
) -> None:
    snapshot = _snapshot()

    service, _, _ = _build_service(
        repository_result={
            "CVE-2021-44228": snapshot,
        },
    )

    threat = Threat(
        id="CVE-2021-44228",
        category=(
            ThreatCategory.VULNERABILITY
        ),
    )

    result = service.enrich_threats(
        [
            threat,
        ]
    )

    assert (
        result.threats[0].category
        is ThreatCategory.VULNERABILITY
    )


def test_transaction_closes_before_threat_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = _snapshot()

    service, unit_of_work, _ = (
        _build_service(
            repository_result={
                "CVE-2021-44228": snapshot,
            },
        )
    )

    threat = Threat(
        id="CVE-2021-44228",
    )

    original_apply = (
        service._apply_epss_to_threats
    )

    def guarded_apply(
        *,
        threats: list[Threat],
        epss_lookup: Mapping[
            str,
            EPSSSnapshot,
        ],
    ) -> int:
        assert unit_of_work.exited is True

        return original_apply(
            threats=threats,
            epss_lookup=epss_lookup,
        )

    monkeypatch.setattr(
        service,
        "_apply_epss_to_threats",
        guarded_apply,
    )

    service.enrich_threats(
        [
            threat,
        ]
    )

    assert threat.epss_score == 0.99999
    assert unit_of_work.commit_count == 0


def test_enrich_threats_rejects_historical_date(
) -> None:
    service, unit_of_work, repository = (
        _build_service()
    )

    with pytest.raises(
        ValueError,
        match=(
            "historical EPSS enrichment "
            "is not supported by local storage"
        ),
    ):
        service.enrich_threats(
            [
                Threat(
                    id="CVE-2021-44228",
                ),
            ],
            date="2026-07-29",
        )

    assert repository.calls == []
    assert unit_of_work.enter_count == 0