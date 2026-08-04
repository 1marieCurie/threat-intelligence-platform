from __future__ import annotations

import os
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[2]

load_dotenv(
    dotenv_path=PROJECT_ROOT / ".env",
    override=False,
)


import pytest
from sqlalchemy import create_engine, delete, func, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from application.models.canonical_vulnerability_observation import (
    CanonicalVulnerabilityObservation,
)
from application.services.canonical_vulnerability_correlation_service import (
    CanonicalCorrelationConflictError,
    CanonicalVulnerabilityCorrelationService,
)
from domain.canonical_vulnerability import CanonicalVulnerability
from domain.vulnerability_evidence import VulnerabilityEvidence
from domain.vulnerability_identifier import VulnerabilityIdentifier
from infrastructure.persistence.models.canonical import (
    CanonicalVulnerabilityEvidenceModel,
    CanonicalVulnerabilityIdentifierModel,
    CanonicalVulnerabilityModel,
)
from infrastructure.persistence.sqlalchemy import (
    SqlAlchemyUnitOfWork,
    create_ingestion_engine,
    create_session_factory,
)
from infrastructure.persistence.sqlalchemy.repositories.canonical_vulnerability_repository import (
    SqlAlchemyCanonicalVulnerabilityRepository,
)


pytestmark = pytest.mark.integration


@dataclass(slots=True)
class DatabaseContext:
    owner_session_factory: sessionmaker[Session]

    ingestion_session_factory: sessionmaker[Session]

    tracked_ids: set[UUID] = field(
        default_factory=set
    )

    def new_id(self) -> UUID:
        vulnerability_id = uuid4()

        self.tracked_ids.add(
            vulnerability_id
        )

        return vulnerability_id


def _owner_engine() -> Engine:
    database_url = os.environ.get(
        "MIGRATION_DATABASE_URL"
    )

    if not database_url:
        raise RuntimeError(
            "MIGRATION_DATABASE_URL is not defined"
        )

    return create_engine(
        database_url,
        pool_pre_ping=True,
    )


def _owner_session_factory(
    engine: Engine,
) -> sessionmaker[Session]:
    return sessionmaker(
        bind=engine,
        class_=Session,
        autoflush=False,
        expire_on_commit=False,
    )


def _cleanup(
    context: DatabaseContext,
) -> None:
    if not context.tracked_ids:
        return

    with (
        context.owner_session_factory()
        as session
    ):
        session.execute(
            text(
                "SET ROLE threat_intel_owner"
            )
        )

        session.execute(
            delete(
                CanonicalVulnerabilityModel
            ).where(
                CanonicalVulnerabilityModel
                .id
                .in_(
                    context.tracked_ids
                )
            )
        )

        session.commit()


@pytest.fixture
def database_context(
) -> Iterator[DatabaseContext]:
    owner_engine = _owner_engine()

    ingestion_engine: Engine | None = None

    context: DatabaseContext | None = None

    try:
        ingestion_engine = (
            create_ingestion_engine()
        )

        context = DatabaseContext(
            owner_session_factory=(
                _owner_session_factory(
                    owner_engine
                )
            ),
            ingestion_session_factory=(
                create_session_factory(
                    ingestion_engine
                )
            ),
        )

        yield context

    finally:
        try:
            if context is not None:
                _cleanup(
                    context
                )

        finally:
            if ingestion_engine is not None:
                ingestion_engine.dispose()

            owner_engine.dispose()


def _unique_cve() -> str:
    serial_number = (
        100_000_000
        + uuid4().int % 900_000_000
    )

    return (
        f"CVE-2026-{serial_number}"
    )


def _unique_ghsa() -> str:
    token = uuid4().hex.upper()

    return (
        f"GHSA-{token[:4]}-"
        f"{token[4:8]}-"
        f"{token[8:12]}"
    )


def _cve(
    value: str,
    *,
    primary: bool = True,
) -> VulnerabilityIdentifier:
    return VulnerabilityIdentifier(
        namespace="CVE",
        value=value,
        is_primary=primary,
    )


def _ghsa(
    value: str,
    *,
    primary: bool = False,
) -> VulnerabilityIdentifier:
    return VulnerabilityIdentifier(
        namespace="GHSA",
        value=value,
        is_primary=primary,
    )


def _evidence(
    *,
    source: str,
    record_key: str,
    observed_at: datetime,
    last_observed_at: (
        datetime | None
    ) = None,
    normalized_record_id: (
        str | None
    ) = None,
    record_hash: str | None = None,
) -> VulnerabilityEvidence:
    return VulnerabilityEvidence(
        source=source,
        source_record_key=record_key,
        normalized_record_id=(
            normalized_record_id
            or record_key
        ),
        evidence_type=(
            "epss_snapshot"
            if source == "epss"
            else "vulnerability_record"
        ),
        correlation_rule="exact_cve",
        observed_at=observed_at,
        last_observed_at=(
            last_observed_at
            or observed_at
        ),
        correlation_confidence=1.0,
        record_hash=record_hash,
    )


def _observation(
    *,
    identifiers: tuple[
        VulnerabilityIdentifier,
        ...,
    ],
    evidence: VulnerabilityEvidence,
    status: str = "provisional",
) -> CanonicalVulnerabilityObservation:
    return CanonicalVulnerabilityObservation(
        identifiers=identifiers,
        evidence=evidence,
        suggested_status=status,
    )


def _service(
    context: DatabaseContext,
    *,
    uuid_factory: (
        Callable[[], UUID]
        | None
    ) = None,
) -> CanonicalVulnerabilityCorrelationService:
    return (
        CanonicalVulnerabilityCorrelationService(
            unit_of_work=(
                SqlAlchemyUnitOfWork(
                    session_factory=(
                        context
                        .ingestion_session_factory
                    )
                )
            ),
            uuid_factory=(
                uuid_factory
                or context.new_id
            ),
        )
    )


def _load_by_identifier(
    context: DatabaseContext,
    identifier: VulnerabilityIdentifier,
) -> CanonicalVulnerability | None:
    with (
        context.ingestion_session_factory()
        as session
    ):
        repository = (
            SqlAlchemyCanonicalVulnerabilityRepository(
                session=session
            )
        )

        return (
            repository
            .find_many_by_identifiers(
                [identifier]
            )
            .get(
                identifier.key
            )
        )


def _load_by_evidence(
    context: DatabaseContext,
    evidence: VulnerabilityEvidence,
) -> CanonicalVulnerability | None:
    with (
        context.ingestion_session_factory()
        as session
    ):
        repository = (
            SqlAlchemyCanonicalVulnerabilityRepository(
                session=session
            )
        )

        return (
            repository
            .find_many_by_evidences(
                [evidence]
            )
            .get(
                evidence.key
            )
        )


def _row_counts(
    context: DatabaseContext,
    vulnerability_id: UUID,
) -> tuple[int, int, int]:
    with (
        context.ingestion_session_factory()
        as session
    ):
        aggregate_count = session.scalar(
            select(
                func.count()
            )
            .select_from(
                CanonicalVulnerabilityModel
            )
            .where(
                CanonicalVulnerabilityModel.id
                == vulnerability_id
            )
        )

        identifier_count = session.scalar(
            select(
                func.count()
            )
            .select_from(
                CanonicalVulnerabilityIdentifierModel
            )
            .where(
                (
                    CanonicalVulnerabilityIdentifierModel
                    .vulnerability_id
                )
                == vulnerability_id
            )
        )

        evidence_count = session.scalar(
            select(
                func.count()
            )
            .select_from(
                CanonicalVulnerabilityEvidenceModel
            )
            .where(
                (
                    CanonicalVulnerabilityEvidenceModel
                    .vulnerability_id
                )
                == vulnerability_id
            )
        )

    return (
        int(
            aggregate_count
            or 0
        ),
        int(
            identifier_count
            or 0
        ),
        int(
            evidence_count
            or 0
        ),
    )


def test_ghsa_only_creates_committed_provisional_aggregate(
    database_context: DatabaseContext,
) -> None:
    now = datetime.now(
        UTC
    ).replace(
        microsecond=0
    )

    vulnerability_id = (
        database_context.new_id()
    )

    ghsa = _ghsa(
        _unique_ghsa(),
        primary=True,
    )

    result = _service(
        database_context,
        uuid_factory=lambda: (
            vulnerability_id
        ),
    ).correlate(
        [
            _observation(
                identifiers=(
                    ghsa,
                ),
                evidence=_evidence(
                    source=(
                        "github_advisory"
                    ),
                    record_key=(
                        ghsa.value
                    ),
                    observed_at=now,
                ),
            )
        ]
    )

    assert result.created == 1
    assert result.updated == 0
    assert result.persisted == 1

    loaded = _load_by_identifier(
        database_context,
        ghsa,
    )

    assert loaded is not None

    assert loaded.id == (
        vulnerability_id
    )

    assert loaded.status == (
        "provisional"
    )

    assert (
        loaded.primary_identifier.key
        == ghsa.key
    )

    assert loaded.sources == (
        "github_advisory",
    )

    assert _row_counts(
        database_context,
        vulnerability_id,
    ) == (
        1,
        1,
        1,
    )


def test_existing_ghsa_is_enriched_with_cve_without_losing_evidence(
    database_context: DatabaseContext,
) -> None:
    observed_at = datetime.now(
        UTC
    ).replace(
        microsecond=0
    )

    later_at = (
        observed_at
        + timedelta(
            hours=2
        )
    )

    vulnerability_id = (
        database_context.new_id()
    )

    ghsa = _ghsa(
        _unique_ghsa(),
        primary=True,
    )

    service = _service(
        database_context,
        uuid_factory=lambda: (
            vulnerability_id
        ),
    )

    service.correlate(
        [
            _observation(
                identifiers=(
                    ghsa,
                ),
                evidence=_evidence(
                    source=(
                        "github_advisory"
                    ),
                    record_key=(
                        ghsa.value
                    ),
                    observed_at=(
                        observed_at
                    ),
                    normalized_record_id=(
                        "github:"
                        f"{ghsa.value}:"
                        "initial"
                    ),
                    record_hash=(
                        "a" * 64
                    ),
                ),
            )
        ]
    )

    cve = _cve(
        _unique_cve()
    )

    result = service.correlate(
        [
            _observation(
                identifiers=(
                    cve,
                    _ghsa(
                        ghsa.value
                    ),
                ),
                evidence=_evidence(
                    source=(
                        "github_advisory"
                    ),
                    record_key=(
                        ghsa.value
                    ),
                    observed_at=(
                        later_at
                    ),
                    normalized_record_id=(
                        "github:"
                        f"{ghsa.value}:"
                        "later"
                    ),
                ),
                status="active",
            )
        ]
    )

    assert result.created == 0
    assert result.updated == 1

    loaded = _load_by_identifier(
        database_context,
        cve,
    )

    assert loaded is not None

    assert loaded.id == (
        vulnerability_id
    )

    assert loaded.status == "active"

    assert (
        loaded.primary_identifier.key
        == cve.key
    )

    assert {
        identifier.key
        for identifier
        in loaded.identifiers
    } == {
        cve.key,
        ghsa.key,
    }

    assert len(
        loaded.evidences
    ) == 1

    persisted_evidence = (
        loaded.evidences[0]
    )

    assert (
        persisted_evidence.observed_at
        == observed_at
    )

    assert (
        persisted_evidence
        .last_observed_at
        == later_at
    )

    assert (
        persisted_evidence.record_hash
        == "a" * 64
    )


def test_epss_only_cve_creates_provisional_aggregate(
    database_context: DatabaseContext,
) -> None:
    now = datetime.now(
        UTC
    ).replace(
        microsecond=0
    )

    vulnerability_id = (
        database_context.new_id()
    )

    cve = _cve(
        _unique_cve()
    )

    result = _service(
        database_context,
        uuid_factory=lambda: (
            vulnerability_id
        ),
    ).correlate(
        [
            _observation(
                identifiers=(
                    cve,
                ),
                evidence=_evidence(
                    source="epss",
                    record_key=(
                        cve.value
                    ),
                    observed_at=now,
                ),
            )
        ]
    )

    assert result.created == 1
    assert result.updated == 0

    loaded = _load_by_identifier(
        database_context,
        cve,
    )

    assert loaded is not None

    assert loaded.id == (
        vulnerability_id
    )

    assert loaded.status == (
        "provisional"
    )

    assert (
        loaded.primary_identifier.key
        == cve.key
    )

    assert loaded.sources == (
        "epss",
    )


def test_same_cve_from_three_sources_creates_one_active_aggregate(
    database_context: DatabaseContext,
) -> None:
    now = datetime.now(
        UTC
    ).replace(
        microsecond=0
    )

    vulnerability_id = (
        database_context.new_id()
    )

    cve = _cve(
        _unique_cve()
    )

    ghsa = _ghsa(
        _unique_ghsa()
    )

    result = _service(
        database_context,
        uuid_factory=lambda: (
            vulnerability_id
        ),
    ).correlate(
        [
            _observation(
                identifiers=(
                    cve,
                    ghsa,
                ),
                evidence=_evidence(
                    source=(
                        "github_advisory"
                    ),
                    record_key=(
                        ghsa.value
                    ),
                    observed_at=now,
                ),
                status="active",
            ),
            _observation(
                identifiers=(
                    cve,
                ),
                evidence=_evidence(
                    source="cisa_kev",
                    record_key=(
                        cve.value
                    ),
                    observed_at=(
                        now
                        + timedelta(
                            minutes=1
                        )
                    ),
                ),
                status="active",
            ),
            _observation(
                identifiers=(
                    cve,
                ),
                evidence=_evidence(
                    source="epss",
                    record_key=(
                        cve.value
                    ),
                    observed_at=(
                        now
                        + timedelta(
                            minutes=2
                        )
                    ),
                ),
            ),
        ]
    )

    assert (
        result.components_built
        == 1
    )

    assert result.created == 1
    assert result.persisted == 1

    loaded = _load_by_identifier(
        database_context,
        cve,
    )

    assert loaded is not None

    assert loaded.id == (
        vulnerability_id
    )

    assert loaded.status == "active"

    assert {
        evidence.source
        for evidence
        in loaded.evidences
    } == {
        "github_advisory",
        "cisa_kev",
        "epss",
    }

    assert len(
        loaded.evidences
    ) == 3


def test_reprocessing_same_batch_is_idempotent(
    database_context: DatabaseContext,
) -> None:
    observed_at = datetime.now(
        UTC
    ).replace(
        microsecond=0
    )

    vulnerability_id = (
        database_context.new_id()
    )

    cve = _cve(
        _unique_cve()
    )

    ghsa = _ghsa(
        _unique_ghsa()
    )

    evidence = _evidence(
        source="github_advisory",
        record_key=ghsa.value,
        observed_at=observed_at,
        last_observed_at=(
            observed_at
            + timedelta(
                minutes=10
            )
        ),
        normalized_record_id=(
            f"github:{ghsa.value}"
        ),
        record_hash=(
            "b" * 64
        ),
    )

    batch = [
        _observation(
            identifiers=(
                cve,
                ghsa,
            ),
            evidence=evidence,
            status="active",
        )
    ]

    service = _service(
        database_context,
        uuid_factory=lambda: (
            vulnerability_id
        ),
    )

    first_result = (
        service.correlate(
            batch
        )
    )

    second_result = (
        service.correlate(
            batch
        )
    )

    assert first_result.created == 1

    assert second_result.created == 0
    assert second_result.updated == 1

    loaded = _load_by_identifier(
        database_context,
        cve,
    )

    assert loaded is not None

    assert loaded.id == (
        vulnerability_id
    )

    assert len(
        loaded.identifiers
    ) == 2

    assert len(
        loaded.evidences
    ) == 1

    assert (
        loaded.evidences[0]
        .observed_at
        == evidence.observed_at
    )

    assert (
        loaded.evidences[0]
        .last_observed_at
        == evidence.last_observed_at
    )

    assert _row_counts(
        database_context,
        vulnerability_id,
    ) == (
        1,
        2,
        1,
    )


def test_conflict_rolls_back_entire_batch_without_partial_write(
    database_context: DatabaseContext,
) -> None:
    now = datetime.now(
        UTC
    ).replace(
        microsecond=0
    )

    first_id = (
        database_context.new_id()
    )

    second_id = (
        database_context.new_id()
    )

    generated_ids = iter(
        (
            first_id,
            second_id,
        )
    )

    first_cve = _cve(
        _unique_cve()
    )

    second_ghsa = _ghsa(
        _unique_ghsa(),
        primary=True,
    )

    _service(
        database_context,
        uuid_factory=lambda: next(
            generated_ids
        ),
    ).correlate(
        [
            _observation(
                identifiers=(
                    first_cve,
                ),
                evidence=_evidence(
                    source="epss",
                    record_key=(
                        first_cve.value
                    ),
                    observed_at=now,
                ),
            ),
            _observation(
                identifiers=(
                    second_ghsa,
                ),
                evidence=_evidence(
                    source=(
                        "github_advisory"
                    ),
                    record_key=(
                        second_ghsa.value
                    ),
                    observed_at=now,
                ),
            ),
        ]
    )

    first_before = (
        _load_by_identifier(
            database_context,
            first_cve,
        )
    )

    second_before = (
        _load_by_identifier(
            database_context,
            second_ghsa,
        )
    )

    assert first_before is not None
    assert second_before is not None

    independent_id = (
        database_context.new_id()
    )

    independent_cve = _cve(
        _unique_cve()
    )

    conflict_evidence = _evidence(
        source="github_advisory",
        record_key=_unique_ghsa(),
        observed_at=(
            now
            + timedelta(
                hours=1
            )
        ),
    )

    with pytest.raises(
        CanonicalCorrelationConflictError,
        match=(
            "several canonical "
            "vulnerabilities"
        ),
    ):
        _service(
            database_context,
            uuid_factory=lambda: (
                independent_id
            ),
        ).correlate(
            [
                _observation(
                    identifiers=(
                        independent_cve,
                    ),
                    evidence=_evidence(
                        source="epss",
                        record_key=(
                            independent_cve
                            .value
                        ),
                        observed_at=(
                            now
                            + timedelta(
                                hours=1
                            )
                        ),
                    ),
                ),
                _observation(
                    identifiers=(
                        first_cve,
                        _ghsa(
                            second_ghsa
                            .value
                        ),
                    ),
                    evidence=(
                        conflict_evidence
                    ),
                    status="active",
                ),
            ]
        )

    assert (
        _load_by_identifier(
            database_context,
            independent_cve,
        )
        is None
    )

    assert (
        _load_by_evidence(
            database_context,
            conflict_evidence,
        )
        is None
    )

    assert (
        _load_by_identifier(
            database_context,
            first_cve,
        )
        == first_before
    )

    assert (
        _load_by_identifier(
            database_context,
            second_ghsa,
        )
        == second_before
    )


def test_later_partial_observation_preserves_all_existing_evidence(
    database_context: DatabaseContext,
) -> None:
    observed_at = datetime.now(
        UTC
    ).replace(
        microsecond=0
    )

    vulnerability_id = (
        database_context.new_id()
    )

    cve = _cve(
        _unique_cve()
    )

    ghsa = _ghsa(
        _unique_ghsa()
    )

    github_evidence = _evidence(
        source="github_advisory",
        record_key=ghsa.value,
        observed_at=observed_at,
    )

    cisa_evidence = _evidence(
        source="cisa_kev",
        record_key=cve.value,
        observed_at=(
            observed_at
            + timedelta(
                minutes=1
            )
        ),
    )

    epss_evidence = _evidence(
        source="epss",
        record_key=cve.value,
        observed_at=(
            observed_at
            + timedelta(
                minutes=2
            )
        ),
    )

    service = _service(
        database_context,
        uuid_factory=lambda: (
            vulnerability_id
        ),
    )

    service.correlate(
        [
            _observation(
                identifiers=(
                    cve,
                    ghsa,
                ),
                evidence=(
                    github_evidence
                ),
                status="active",
            ),
            _observation(
                identifiers=(
                    cve,
                ),
                evidence=(
                    cisa_evidence
                ),
                status="active",
            ),
            _observation(
                identifiers=(
                    cve,
                ),
                evidence=(
                    epss_evidence
                ),
            ),
        ]
    )

    later_epss = _evidence(
        source="epss",
        record_key=cve.value,
        observed_at=(
            observed_at
            + timedelta(
                hours=2
            )
        ),
        last_observed_at=(
            observed_at
            + timedelta(
                hours=3
            )
        ),
        normalized_record_id=(
            f"epss:{cve.value}:later"
        ),
    )

    result = service.correlate(
        [
            _observation(
                identifiers=(
                    cve,
                ),
                evidence=later_epss,
            )
        ]
    )

    assert result.created == 0
    assert result.updated == 1

    loaded = _load_by_identifier(
        database_context,
        cve,
    )

    assert loaded is not None
    assert loaded.status == "active"

    assert {
        evidence.key
        for evidence
        in loaded.evidences
    } == {
        github_evidence.key,
        cisa_evidence.key,
        epss_evidence.key,
    }

    persisted_epss = next(
        evidence
        for evidence
        in loaded.evidences
        if (
            evidence.key
            == epss_evidence.key
        )
    )

    assert (
        persisted_epss.observed_at
        == epss_evidence.observed_at
    )

    assert (
        persisted_epss
        .last_observed_at
        == later_epss
        .last_observed_at
    )