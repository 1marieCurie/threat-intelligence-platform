from __future__ import annotations

from collections.abc import Iterable
from datetime import (
    UTC,
    date,
    datetime,
    timedelta,
)
from types import TracebackType
from typing import (
    Self,
    cast,
)
from unittest.mock import Mock
from uuid import (
    UUID,
    uuid4,
)

import pytest

from application.models.cisa_kev_canonical_source_record import (
    CisaKevCanonicalSourceRecord,
)
from application.models.github_advisory_canonical_source_record import (
    GitHubAdvisoryCanonicalSourceRecord,
)
from application.ports.outbound.canonical_cwe_enrichment_unit_of_work import (
    CanonicalCWEEnrichmentUnitOfWork,
)
from application.ports.outbound.canonical_vulnerability_weakness_repository import (
    CanonicalVulnerabilityWeaknessKey,
    CanonicalVulnerabilityWeaknessRepository,
)
from application.services.canonical_cwe_association_builder import (
    CanonicalCWEAssociationBuilder,
)
from application.services.canonical_cwe_enrichment_service import (
    CanonicalCWEEnrichmentConflictError,
    CanonicalCWEEnrichmentError,
    CanonicalCWEEnrichmentResolutionError,
    CanonicalCWEEnrichmentService,
)
from application.services.cwe_lookup_service import (
    CWELookupService,
)
from domain.canonical_vulnerability import (
    CanonicalVulnerability,
)
from domain.canonical_vulnerability_weakness import (
    CanonicalVulnerabilityWeakness,
)
from domain.cwe_weakness import (
    CWEWeakness,
)
from domain.vulnerability_evidence import (
    VulnerabilityEvidence,
)
from domain.vulnerability_identifier import (
    VulnerabilityIdentifier,
)


_NOW = datetime(
    2026,
    8,
    5,
    10,
    0,
    tzinfo=UTC,
)

_FIRST_RECORD_ID = UUID(
    "00000000-0000-0000-0000-000000000001"
)

_SECOND_RECORD_ID = UUID(
    "00000000-0000-0000-0000-000000000002"
)


class _WeaknessRepository:
    def __init__(
        self,
        *,
        forced_result: int | None = None,
    ) -> None:
        self.forced_result = forced_result
        self.upsert_calls = 0

        self.values: list[
            CanonicalVulnerabilityWeakness
        ] = []

    def find_many_by_keys(
        self,
        keys: Iterable[
            CanonicalVulnerabilityWeaknessKey
        ],
    ) -> dict[
        CanonicalVulnerabilityWeaknessKey,
        CanonicalVulnerabilityWeakness,
    ]:
        del keys
        return {}

    def upsert_many(
        self,
        weaknesses: Iterable[
            CanonicalVulnerabilityWeakness
        ],
    ) -> int:
        self.upsert_calls += 1

        self.values = list(
            weaknesses
        )

        if self.forced_result is not None:
            return self.forced_result

        return len(
            {
                weakness.key
                for weakness in self.values
            }
        )


class _FakeUnitOfWork:
    def __init__(
        self,
        *,
        repository: (
            CanonicalVulnerabilityWeaknessRepository
        ),
    ) -> None:
        self.canonical_vulnerability_weaknesses = (
            repository
        )

        self.enter_count = 0
        self.exit_count = 0
        self.commit_count = 0
        self.rollback_count = 0

    def __enter__(
        self,
    ) -> Self:
        self.enter_count += 1
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

        if exc_type is not None:
            self.rollback()

    def commit(
        self,
    ) -> None:
        self.commit_count += 1

    def rollback(
        self,
    ) -> None:
        self.rollback_count += 1


def _weakness(
    cwe_id: str,
) -> CWEWeakness:
    return CWEWeakness(
        id=cwe_id,
        name=f"Name {cwe_id}",
        description=f"Description {cwe_id}",
    )


def _github_record(
    *,
    normalized_record_id: UUID = (
        _FIRST_RECORD_ID
    ),
    cwe_ids: tuple[str, ...] = (
        "CWE-79",
    ),
    normalized_at: datetime = _NOW,
) -> GitHubAdvisoryCanonicalSourceRecord:
    return GitHubAdvisoryCanonicalSourceRecord(
        normalized_record_id=(
            normalized_record_id
        ),
        ghsa_id="GHSA-AAAA-BBBB-CCCC",
        cve_id="CVE-2026-12345",
        cwe_ids=cwe_ids,
        normalized_at=normalized_at,
        updated_at=normalized_at,
    )


def _cisa_record(
    *,
    cwe_ids: tuple[str, ...] = (
        "CWE-89",
    ),
) -> CisaKevCanonicalSourceRecord:
    return CisaKevCanonicalSourceRecord(
        normalized_record_id=(
            _SECOND_RECORD_ID
        ),
        cve_id="CVE-2026-54321",
        cwe_ids=cwe_ids,
        date_added=date(
            2026,
            8,
            4,
        ),
        normalized_at=_NOW,
    )


def _aggregate(
    *,
    vulnerability_id: UUID | None = None,
    source: str,
    source_record_key: str,
    status: str = "active",
) -> CanonicalVulnerability:
    identifier_namespace = (
        "GHSA"
        if source == "github_advisory"
        else "CVE"
    )

    identifier = VulnerabilityIdentifier(
        namespace=identifier_namespace,
        value=source_record_key,
        is_primary=True,
    )

    evidence = VulnerabilityEvidence(
        source=source,
        source_record_key=(
            source_record_key
        ),
        normalized_record_id=str(
            uuid4()
        ),
        evidence_type=(
            "github_security_advisory"
            if source == "github_advisory"
            else (
                "known_exploited_vulnerability"
            )
        ),
        correlation_rule=(
            "exact_ghsa"
            if source == "github_advisory"
            else "exact_cve"
        ),
        observed_at=_NOW,
        last_observed_at=_NOW,
        correlation_confidence=1.0,
    )

    return CanonicalVulnerability(
        id=(
            vulnerability_id
            or uuid4()
        ),
        identifiers=(
            identifier,
        ),
        evidences=(
            evidence,
        ),
        created_at=_NOW,
        updated_at=_NOW,
        status=status,
        correlation_version=1,
    )


def _build_service(
    *,
    lookup_result: dict[
        str,
        CWEWeakness,
    ],
    repository: (
        _WeaknessRepository | None
    ) = None,
    max_records: int = 5_000,
) -> tuple[
    CanonicalCWEEnrichmentService,
    Mock,
    _FakeUnitOfWork,
    _WeaknessRepository,
]:
    lookup_mock = Mock(
        spec=CWELookupService,
    )

    lookup_mock \
        .find_many_by_cwe_ids \
        .return_value = lookup_result

    effective_repository = (
        repository
        or _WeaknessRepository()
    )

    unit_of_work = _FakeUnitOfWork(
        repository=effective_repository,
    )

    service = CanonicalCWEEnrichmentService(
        cwe_lookup=cast(
            CWELookupService,
            lookup_mock,
        ),
        builder=(
            CanonicalCWEAssociationBuilder()
        ),
        unit_of_work=cast(
            CanonicalCWEEnrichmentUnitOfWork,
            unit_of_work,
        ),
        max_records=max_records,
    )

    return (
        service,
        lookup_mock,
        unit_of_work,
        effective_repository,
    )


def test_constructor_rejects_missing_dependencies(
) -> None:
    lookup = Mock(
        spec=CWELookupService,
    )

    builder = (
        CanonicalCWEAssociationBuilder()
    )

    repository = _WeaknessRepository()

    unit_of_work = _FakeUnitOfWork(
        repository=repository,
    )

    with pytest.raises(
        ValueError,
        match="cwe_lookup must not be None",
    ):
        CanonicalCWEEnrichmentService(
            cwe_lookup=None,  # type: ignore[arg-type]
            builder=builder,
            unit_of_work=unit_of_work,
        )

    with pytest.raises(
        ValueError,
        match="builder must not be None",
    ):
        CanonicalCWEEnrichmentService(
            cwe_lookup=cast(
                CWELookupService,
                lookup,
            ),
            builder=None,  # type: ignore[arg-type]
            unit_of_work=unit_of_work,
        )

    with pytest.raises(
        ValueError,
        match="unit_of_work must not be None",
    ):
        CanonicalCWEEnrichmentService(
            cwe_lookup=cast(
                CWELookupService,
                lookup,
            ),
            builder=builder,
            unit_of_work=None,  # type: ignore[arg-type]
        )


def test_empty_batch_performs_no_lookup_or_write(
) -> None:
    (
        service,
        lookup,
        unit_of_work,
        repository,
    ) = _build_service(
        lookup_result={}
    )

    result = service.enrich(
        records=[],
        aggregates=[],
    )

    assert result.records_received == 0
    assert result.persisted == 0

    lookup \
        .find_many_by_cwe_ids \
        .assert_not_called()

    assert repository.upsert_calls == 0
    assert unit_of_work.enter_count == 0
    assert unit_of_work.commit_count == 0


def test_enriches_github_record_with_one_lookup_and_write(
) -> None:
    record = _github_record(
        cwe_ids=(
            "CWE-79",
            "CWE-999",
        )
    )

    aggregate = _aggregate(
        source="github_advisory",
        source_record_key=record.ghsa_id,
    )

    (
        service,
        lookup,
        unit_of_work,
        repository,
    ) = _build_service(
        lookup_result={
            "CWE-79": _weakness(
                "CWE-79"
            ),
        }
    )

    result = service.enrich(
        records=[
            record,
        ],
        aggregates=[
            aggregate,
        ],
    )

    assert result.records_received == 1

    assert (
        result.records_with_cwe_references
        == 1
    )

    assert result.records_enriched == 1

    assert result.missing_cwe_ids == (
        "CWE-999",
    )

    assert result.association_candidates == 1
    assert result.unique_associations == 1
    assert result.persisted == 1

    lookup \
        .find_many_by_cwe_ids \
        .assert_called_once_with(
            [
                "CWE-79",
                "CWE-999",
            ]
        )

    assert repository.upsert_calls == 1
    assert len(repository.values) == 1

    association = repository.values[0]

    assert (
        association.vulnerability_id
        == aggregate.id
    )

    assert association.cwe_id == "CWE-79"

    assert (
        association.source
        == "github_advisory"
    )

    assert (
        association.source_record_key
        == record.ghsa_id
    )

    assert unit_of_work.enter_count == 1
    assert unit_of_work.commit_count == 1
    assert unit_of_work.rollback_count == 0


def test_enriches_mixed_sources_with_one_upsert(
) -> None:
    github_record = _github_record()

    cisa_record = _cisa_record()

    github_aggregate = _aggregate(
        source="github_advisory",
        source_record_key=(
            github_record.ghsa_id
        ),
    )

    cisa_aggregate = _aggregate(
        source="cisa_kev",
        source_record_key=(
            cisa_record.cve_id
        ),
    )

    (
        service,
        lookup,
        unit_of_work,
        repository,
    ) = _build_service(
        lookup_result={
            "CWE-79": _weakness(
                "CWE-79"
            ),
            "CWE-89": _weakness(
                "CWE-89"
            ),
        }
    )

    result = service.enrich(
        records=[
            github_record,
            cisa_record,
        ],
        aggregates=[
            github_aggregate,
            cisa_aggregate,
        ],
    )

    assert result.records_received == 2
    assert result.records_enriched == 2
    assert result.persisted == 2

    assert repository.upsert_calls == 1

    assert {
        value.source
        for value in repository.values
    } == {
        "github_advisory",
        "cisa_kev",
    }

    lookup \
        .find_many_by_cwe_ids \
        .assert_called_once_with(
            [
                "CWE-79",
                "CWE-89",
            ]
        )

    assert unit_of_work.commit_count == 1


def test_missing_catalogue_entries_are_not_persisted(
) -> None:
    record = _github_record(
        cwe_ids=(
            "CWE-999",
        )
    )

    (
        service,
        lookup,
        unit_of_work,
        repository,
    ) = _build_service(
        lookup_result={}
    )

    result = service.enrich(
        records=[
            record,
        ],
        aggregates=[],
    )

    assert result.records_enriched == 0

    assert (
        result.records_without_catalogued_cwe
        == 1
    )

    assert result.missing_cwe_ids == (
        "CWE-999",
    )

    assert result.persisted == 0

    lookup \
        .find_many_by_cwe_ids \
        .assert_called_once_with(
            [
                "CWE-999",
            ]
        )

    assert repository.upsert_calls == 0
    assert unit_of_work.enter_count == 0


def test_catalogued_cwe_requires_resolved_aggregate(
) -> None:
    record = _github_record()

    (
        service,
        _,
        unit_of_work,
        repository,
    ) = _build_service(
        lookup_result={
            "CWE-79": _weakness(
                "CWE-79"
            ),
        }
    )

    with pytest.raises(
        CanonicalCWEEnrichmentResolutionError,
        match=(
            "does not resolve to a canonical "
            "vulnerability"
        ),
    ):
        service.enrich(
            records=[
                record,
            ],
            aggregates=[],
        )

    assert repository.upsert_calls == 0
    assert unit_of_work.enter_count == 0


def test_rejects_evidence_owned_by_multiple_aggregates(
) -> None:
    record = _github_record()

    first = _aggregate(
        source="github_advisory",
        source_record_key=record.ghsa_id,
    )

    second = _aggregate(
        source="github_advisory",
        source_record_key=record.ghsa_id,
    )

    (
        service,
        _,
        unit_of_work,
        repository,
    ) = _build_service(
        lookup_result={
            "CWE-79": _weakness(
                "CWE-79"
            ),
        }
    )

    with pytest.raises(
        CanonicalCWEEnrichmentConflictError,
        match=(
            "belongs to several canonical "
            "vulnerabilities"
        ),
    ):
        service.enrich(
            records=[
                record,
            ],
            aggregates=[
                first,
                second,
            ],
        )

    assert repository.upsert_calls == 0
    assert unit_of_work.enter_count == 0


def test_rejects_terminal_aggregate(
) -> None:
    record = _github_record()

    aggregate = _aggregate(
        source="github_advisory",
        source_record_key=record.ghsa_id,
        status="withdrawn",
    )

    (
        service,
        _,
        unit_of_work,
        repository,
    ) = _build_service(
        lookup_result={
            "CWE-79": _weakness(
                "CWE-79"
            ),
        }
    )

    with pytest.raises(
        CanonicalCWEEnrichmentResolutionError,
        match=(
            "terminal canonical vulnerability"
        ),
    ):
        service.enrich(
            records=[
                record,
            ],
            aggregates=[
                aggregate,
            ],
        )

    assert repository.upsert_calls == 0
    assert unit_of_work.enter_count == 0


def test_duplicate_source_snapshots_remain_idempotent(
) -> None:
    first_record = _github_record(
        normalized_record_id=(
            _FIRST_RECORD_ID
        ),
        normalized_at=_NOW,
    )

    second_record = _github_record(
        normalized_record_id=(
            _SECOND_RECORD_ID
        ),
        normalized_at=(
            _NOW
            + timedelta(hours=1)
        ),
    )

    aggregate = _aggregate(
        source="github_advisory",
        source_record_key=(
            first_record.ghsa_id
        ),
    )

    (
        service,
        _,
        unit_of_work,
        repository,
    ) = _build_service(
        lookup_result={
            "CWE-79": _weakness(
                "CWE-79"
            ),
        }
    )

    result = service.enrich(
        records=[
            first_record,
            second_record,
        ],
        aggregates=[
            aggregate,
        ],
    )

    assert result.association_candidates == 2
    assert result.unique_associations == 1
    assert result.persisted == 1

    assert len(repository.values) == 2
    assert repository.upsert_calls == 1
    assert unit_of_work.commit_count == 1


def test_unexpected_repository_count_rolls_back(
) -> None:
    record = _github_record()

    aggregate = _aggregate(
        source="github_advisory",
        source_record_key=record.ghsa_id,
    )

    repository = _WeaknessRepository(
        forced_result=0
    )

    (
        service,
        _,
        unit_of_work,
        _,
    ) = _build_service(
        lookup_result={
            "CWE-79": _weakness(
                "CWE-79"
            ),
        },
        repository=repository,
    )

    with pytest.raises(
        CanonicalCWEEnrichmentError,
        match=(
            "unexpected persisted "
            "association count"
        ),
    ):
        service.enrich(
            records=[
                record,
            ],
            aggregates=[
                aggregate,
            ],
        )

    assert unit_of_work.commit_count == 0
    assert unit_of_work.rollback_count == 1


def test_rejects_batch_above_configured_limit(
) -> None:
    (
        service,
        lookup,
        unit_of_work,
        repository,
    ) = _build_service(
        lookup_result={},
        max_records=1,
    )

    with pytest.raises(
        ValueError,
        match=(
            "records exceeds the configured "
            "limit of 1"
        ),
    ):
        service.enrich(
            records=[
                _github_record(),
                _cisa_record(),
            ],
            aggregates=[],
        )

    lookup \
        .find_many_by_cwe_ids \
        .assert_not_called()

    assert repository.upsert_calls == 0
    assert unit_of_work.enter_count == 0