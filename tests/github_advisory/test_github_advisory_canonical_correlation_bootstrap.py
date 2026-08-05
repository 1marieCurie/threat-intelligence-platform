from __future__ import annotations

from dataclasses import dataclass
from typing import cast

import pytest

import infrastructure.bootstrap.github_advisory_canonical_correlation as bootstrap_module


@dataclass
class ConstructionState:
    engine_calls: int = 0
    session_factory_calls: int = 0
    unit_of_work_calls: int = 0
    correlation_service_calls: int = 0
    cwe_lookup_service_calls: int = 0
    association_builder_calls: int = 0
    cwe_enrichment_service_calls: int = 0
    observation_builder_calls: int = 0
    processor_calls: int = 0
    job_calls: int = 0


class FakeEngine:
    pass


class FakeSessionFactory:
    pass


class FakeUnitOfWork:
    def __init__(
        self,
        *,
        session_factory: FakeSessionFactory,
    ) -> None:
        self.session_factory = session_factory


class FakeCorrelationService:
    def __init__(
        self,
        *,
        unit_of_work: FakeUnitOfWork,
        max_observations: int,
    ) -> None:
        self.unit_of_work = unit_of_work
        self.max_observations = max_observations


class FakeCWELookupService:
    def __init__(
        self,
        *,
        unit_of_work: FakeUnitOfWork,
    ) -> None:
        self.unit_of_work = unit_of_work


class FakeAssociationBuilder:
    pass


class FakeCWEEnrichmentService:
    def __init__(
        self,
        *,
        unit_of_work: FakeUnitOfWork,
        cwe_lookup: FakeCWELookupService,
        builder: FakeAssociationBuilder,
        max_records: int,
    ) -> None:
        self.unit_of_work = unit_of_work
        self.cwe_lookup = cwe_lookup
        self.builder = builder
        self.max_records = max_records


class FakeObservationBuilder:
    pass


class FakeProcessor:
    def __init__(
        self,
        *,
        session_factory: FakeSessionFactory,
        builder: FakeObservationBuilder,
        correlation_service: FakeCorrelationService,
        cwe_enrichment_service: FakeCWEEnrichmentService,
    ) -> None:
        self.session_factory = session_factory
        self.builder = builder
        self.correlation_service = correlation_service
        self.cwe_enrichment_service = (
            cwe_enrichment_service
        )


class FakeJob:
    def __init__(
        self,
        *,
        processor: FakeProcessor,
        batch_size: int,
        max_batches: int,
    ) -> None:
        self.processor = processor
        self.batch_size = batch_size
        self.max_batches = max_batches


def _install_fakes(
    monkeypatch: pytest.MonkeyPatch,
) -> ConstructionState:
    state = ConstructionState()

    engine = FakeEngine()
    session_factory = FakeSessionFactory()

    def create_engine() -> FakeEngine:
        state.engine_calls += 1
        return engine

    def create_factory(
        received_engine: FakeEngine,
    ) -> FakeSessionFactory:
        assert received_engine is engine

        state.session_factory_calls += 1
        return session_factory

    def build_unit_of_work(
        *,
        session_factory: FakeSessionFactory,
    ) -> FakeUnitOfWork:
        state.unit_of_work_calls += 1

        return FakeUnitOfWork(
            session_factory=session_factory,
        )

    def build_correlation_service(
        *,
        unit_of_work: FakeUnitOfWork,
        max_observations: int,
    ) -> FakeCorrelationService:
        state.correlation_service_calls += 1

        return FakeCorrelationService(
            unit_of_work=unit_of_work,
            max_observations=max_observations,
        )

    def build_lookup_service(
        *,
        unit_of_work: FakeUnitOfWork,
    ) -> FakeCWELookupService:
        state.cwe_lookup_service_calls += 1

        return FakeCWELookupService(
            unit_of_work=unit_of_work,
        )

    def build_association_builder(
    ) -> FakeAssociationBuilder:
        state.association_builder_calls += 1
        return FakeAssociationBuilder()

    def build_enrichment_service(
        *,
        unit_of_work: FakeUnitOfWork,
        cwe_lookup: FakeCWELookupService,
        builder: FakeAssociationBuilder,
        max_records: int,
    ) -> FakeCWEEnrichmentService:
        state.cwe_enrichment_service_calls += 1

        return FakeCWEEnrichmentService(
            unit_of_work=unit_of_work,
            cwe_lookup=cwe_lookup,
            builder=builder,
            max_records=max_records,
        )

    def build_observation_builder(
    ) -> FakeObservationBuilder:
        state.observation_builder_calls += 1
        return FakeObservationBuilder()

    def build_processor(
        *,
        session_factory: FakeSessionFactory,
        builder: FakeObservationBuilder,
        correlation_service: FakeCorrelationService,
        cwe_enrichment_service: FakeCWEEnrichmentService,
    ) -> FakeProcessor:
        state.processor_calls += 1

        return FakeProcessor(
            session_factory=session_factory,
            builder=builder,
            correlation_service=correlation_service,
            cwe_enrichment_service=(
                cwe_enrichment_service
            ),
        )

    def build_job(
        *,
        processor: FakeProcessor,
        batch_size: int,
        max_batches: int,
    ) -> FakeJob:
        state.job_calls += 1

        return FakeJob(
            processor=processor,
            batch_size=batch_size,
            max_batches=max_batches,
        )

    monkeypatch.setattr(
        bootstrap_module,
        "create_ingestion_engine",
        create_engine,
    )

    monkeypatch.setattr(
        bootstrap_module,
        "create_session_factory",
        create_factory,
    )

    monkeypatch.setattr(
        bootstrap_module,
        "SqlAlchemyUnitOfWork",
        build_unit_of_work,
    )

    monkeypatch.setattr(
        bootstrap_module,
        "CanonicalVulnerabilityCorrelationService",
        build_correlation_service,
    )

    monkeypatch.setattr(
        bootstrap_module,
        "CWELookupService",
        build_lookup_service,
    )

    monkeypatch.setattr(
        bootstrap_module,
        "CanonicalCWEAssociationBuilder",
        build_association_builder,
    )

    monkeypatch.setattr(
        bootstrap_module,
        "CanonicalCWEEnrichmentService",
        build_enrichment_service,
    )

    monkeypatch.setattr(
        bootstrap_module,
        "GitHubAdvisoryCanonicalObservationBuilder",
        build_observation_builder,
    )

    monkeypatch.setattr(
        bootstrap_module,
        "SqlAlchemyGitHubAdvisoryCanonicalBatchProcessor",
        build_processor,
    )

    monkeypatch.setattr(
        bootstrap_module,
        "GitHubAdvisoryCanonicalCorrelationJob",
        build_job,
    )

    return state


def test_builds_job_with_default_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(
        bootstrap_module
        .GITHUB_ADVISORY_CANONICAL_BATCH_SIZE_ENV,
        raising=False,
    )

    monkeypatch.delenv(
        bootstrap_module
        .GITHUB_ADVISORY_CANONICAL_MAX_BATCHES_ENV,
        raising=False,
    )

    state = _install_fakes(
        monkeypatch
    )

    result = cast(
        FakeJob,
        bootstrap_module
        .build_github_advisory_canonical_correlation_job(),
    )

    assert result.batch_size == (
        bootstrap_module.DEFAULT_BATCH_SIZE
    )

    assert result.max_batches == (
        bootstrap_module.DEFAULT_MAX_BATCHES
    )

    assert state.engine_calls == 1
    assert state.session_factory_calls == 1
    assert state.unit_of_work_calls == 3

    assert state.correlation_service_calls == 1
    assert state.cwe_lookup_service_calls == 1
    assert state.association_builder_calls == 1
    assert state.cwe_enrichment_service_calls == 1
    assert state.observation_builder_calls == 1
    assert state.processor_calls == 1
    assert state.job_calls == 1

    processor = result.processor

    assert isinstance(
        processor.builder,
        FakeObservationBuilder,
    )

    assert processor.correlation_service.max_observations == (
        bootstrap_module.DEFAULT_BATCH_SIZE
    )

    enrichment_service = (
        processor.cwe_enrichment_service
    )

    assert enrichment_service.max_records == (
        bootstrap_module.DEFAULT_BATCH_SIZE
    )

    assert isinstance(
        enrichment_service.cwe_lookup,
        FakeCWELookupService,
    )

    assert isinstance(
        enrichment_service.builder,
        FakeAssociationBuilder,
    )

    assert (
        processor.session_factory
        is processor
        .correlation_service
        .unit_of_work
        .session_factory
    )

    assert (
        processor.session_factory
        is enrichment_service
        .unit_of_work
        .session_factory
    )

    assert (
        processor.session_factory
        is enrichment_service
        .cwe_lookup
        .unit_of_work
        .session_factory
    )


def test_builds_job_with_environment_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        bootstrap_module
        .GITHUB_ADVISORY_CANONICAL_BATCH_SIZE_ENV,
        "250",
    )

    monkeypatch.setenv(
        bootstrap_module
        .GITHUB_ADVISORY_CANONICAL_MAX_BATCHES_ENV,
        "4000",
    )

    _install_fakes(
        monkeypatch
    )

    result = cast(
        FakeJob,
        bootstrap_module
        .build_github_advisory_canonical_correlation_job(),
    )

    assert result.batch_size == 250
    assert result.max_batches == 4000

    processor = result.processor

    assert (
        processor
        .correlation_service
        .max_observations
        == 250
    )

    assert (
        processor
        .cwe_enrichment_service
        .max_records
        == 250
    )


@pytest.mark.parametrize(
    (
        "variable_name",
        "value",
        "expected_message",
    ),
    [
        (
            bootstrap_module
            .GITHUB_ADVISORY_CANONICAL_BATCH_SIZE_ENV,
            "",
            "must not be empty",
        ),
        (
            bootstrap_module
            .GITHUB_ADVISORY_CANONICAL_BATCH_SIZE_ENV,
            "abc",
            "must be an integer",
        ),
        (
            bootstrap_module
            .GITHUB_ADVISORY_CANONICAL_BATCH_SIZE_ENV,
            "0",
            "must be greater than zero",
        ),
        (
            bootstrap_module
            .GITHUB_ADVISORY_CANONICAL_BATCH_SIZE_ENV,
            "1001",
            "must not exceed 1000",
        ),
        (
            bootstrap_module
            .GITHUB_ADVISORY_CANONICAL_MAX_BATCHES_ENV,
            "",
            "must not be empty",
        ),
        (
            bootstrap_module
            .GITHUB_ADVISORY_CANONICAL_MAX_BATCHES_ENV,
            "-1",
            "must be greater than zero",
        ),
        (
            bootstrap_module
            .GITHUB_ADVISORY_CANONICAL_MAX_BATCHES_ENV,
            "100001",
            "must not exceed 100000",
        ),
    ],
)
def test_rejects_invalid_configuration_before_engine_creation(
    monkeypatch: pytest.MonkeyPatch,
    variable_name: str,
    value: str,
    expected_message: str,
) -> None:
    monkeypatch.delenv(
        bootstrap_module
        .GITHUB_ADVISORY_CANONICAL_BATCH_SIZE_ENV,
        raising=False,
    )

    monkeypatch.delenv(
        bootstrap_module
        .GITHUB_ADVISORY_CANONICAL_MAX_BATCHES_ENV,
        raising=False,
    )

    monkeypatch.setenv(
        variable_name,
        value,
    )

    engine_calls = 0

    def create_engine() -> object:
        nonlocal engine_calls

        engine_calls += 1
        return object()

    monkeypatch.setattr(
        bootstrap_module,
        "create_ingestion_engine",
        create_engine,
    )

    with pytest.raises(
        RuntimeError,
        match=expected_message,
    ):
        (
            bootstrap_module
            .build_github_advisory_canonical_correlation_job()
        )

    assert engine_calls == 0