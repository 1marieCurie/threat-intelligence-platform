from __future__ import annotations

from typing import cast

import pytest
from sqlalchemy.orm import (
    Session,
    sessionmaker,
)

from application.services.canonical_cwe_enrichment_service import (
    CanonicalCWEEnrichmentService,
)
from application.services.canonical_vulnerability_correlation_service import (
    CanonicalVulnerabilityCorrelationService,
)
from application.services.github_advisory_canonical_correlation_batch_service import (
    GitHubAdvisoryCanonicalCorrelationBatchResult,
)
from application.services.github_advisory_canonical_observation_builder import (
    GitHubAdvisoryCanonicalObservationBuilder,
)
import infrastructure.persistence.sqlalchemy.processors.github_advisory_canonical_batch_processor as processor_module
from infrastructure.persistence.sqlalchemy.processors.github_advisory_canonical_batch_processor import (
    SqlAlchemyGitHubAdvisoryCanonicalBatchProcessor,
)


class FakeSession:
    def __init__(
        self,
    ) -> None:
        self.close_calls = 0

    def close(
        self,
    ) -> None:
        self.close_calls += 1


class FakeSessionFactory:
    def __init__(
        self,
    ) -> None:
        self.sessions = []

    def __call__(
        self,
    ):
        session = (
            FakeSession()
        )

        self.sessions.append(
            session
        )

        return session


def test_incremental_processor_builds_incremental_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory = (
        FakeSessionFactory()
    )

    received_incremental_flags = []

    expected_result = cast(
        GitHubAdvisoryCanonicalCorrelationBatchResult,
        object(),
    )

    class FakeSource:
        def __init__(
            self,
            *,
            session,
            incremental_only=False,
        ) -> None:
            assert (
                session
                is factory.sessions[0]
            )

            received_incremental_flags.append(
                incremental_only
            )

    class FakeBatchService:
        DEFAULT_BATCH_SIZE = 500

        def __init__(
            self,
            **_,
        ) -> None:
            pass

        def process_batch(
            self,
            **_,
        ):
            return expected_result

    monkeypatch.setattr(
        processor_module,
        "SqlAlchemyGitHubAdvisoryCanonicalSource",
        FakeSource,
    )

    monkeypatch.setattr(
        processor_module,
        (
            "GitHubAdvisoryCanonicalCorrelation"
            "BatchService"
        ),
        FakeBatchService,
    )

    processor = (
        SqlAlchemyGitHubAdvisoryCanonicalBatchProcessor(
            session_factory=cast(
                sessionmaker[Session],
                factory,
            ),
            builder=cast(
                GitHubAdvisoryCanonicalObservationBuilder,
                object(),
            ),
            correlation_service=cast(
                CanonicalVulnerabilityCorrelationService,
                object(),
            ),
            cwe_enrichment_service=cast(
                CanonicalCWEEnrichmentService,
                object(),
            ),
            incremental_only=True,
        )
    )

    result = (
        processor.process_batch(
            limit=100
        )
    )

    assert (
        result
        is expected_result
    )

    assert (
        received_incremental_flags
        == [
            True
        ]
    )

    assert (
        len(
            factory.sessions
        )
        == 1
    )

    assert (
        factory.sessions[0]
        .close_calls
        == 1
    )


def test_processor_rejects_invalid_incremental_flag():
    factory = (
        FakeSessionFactory()
    )

    with pytest.raises(
        TypeError,
        match=(
            "incremental_only "
            "must be a boolean"
        ),
    ):
        SqlAlchemyGitHubAdvisoryCanonicalBatchProcessor(
            session_factory=cast(
                sessionmaker[Session],
                factory,
            ),
            builder=cast(
                GitHubAdvisoryCanonicalObservationBuilder,
                object(),
            ),
            correlation_service=cast(
                CanonicalVulnerabilityCorrelationService,
                object(),
            ),
            cwe_enrichment_service=cast(
                CanonicalCWEEnrichmentService,
                object(),
            ),
            incremental_only=cast(
                bool,
                "yes",
            ),
        )