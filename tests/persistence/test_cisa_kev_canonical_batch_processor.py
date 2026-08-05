from __future__ import annotations

from dataclasses import dataclass
from typing import cast
from uuid import UUID

import pytest
from sqlalchemy.orm import (
    Session,
    sessionmaker,
)

from application.models.cisa_kev_canonical_source_record import (
    CisaKevCanonicalCursor,
)
from application.services.canonical_cwe_enrichment_service import (
    CanonicalCWEEnrichmentService,
)
from application.services.canonical_vulnerability_correlation_service import (
    CanonicalVulnerabilityCorrelationService,
)
from application.services.cisa_kev_canonical_correlation_batch_service import (
    CisaKevCanonicalCorrelationBatchResult,
)
from application.services.cisa_kev_canonical_observation_builder import (
    CisaKevCanonicalObservationBuilder,
)
import infrastructure.persistence.sqlalchemy.processors.cisa_kev_canonical_batch_processor as processor_module
from infrastructure.persistence.sqlalchemy.processors.cisa_kev_canonical_batch_processor import (
    SqlAlchemyCisaKevCanonicalBatchProcessor,
)


@dataclass
class FakeSession:
    close_calls: int = 0

    def close(
        self,
    ) -> None:
        self.close_calls += 1


class FakeSessionFactory:
    def __init__(
        self,
    ) -> None:
        self.sessions: list[
            FakeSession
        ] = []

    def __call__(
        self,
    ) -> FakeSession:
        session = FakeSession()

        self.sessions.append(
            session
        )

        return session


_BUILDER = cast(
    CisaKevCanonicalObservationBuilder,
    object(),
)

_CORRELATION_SERVICE = cast(
    CanonicalVulnerabilityCorrelationService,
    object(),
)

_CWE_ENRICHMENT_SERVICE = cast(
    CanonicalCWEEnrichmentService,
    object(),
)


def _processor(
    session_factory: object,
) -> (
    SqlAlchemyCisaKevCanonicalBatchProcessor
):
    return (
        SqlAlchemyCisaKevCanonicalBatchProcessor(
            session_factory=cast(
                sessionmaker[Session],
                session_factory,
            ),
            builder=_BUILDER,
            correlation_service=(
                _CORRELATION_SERVICE
            ),
            cwe_enrichment_service=(
                _CWE_ENRICHMENT_SERVICE
            ),
        )
    )


def _cursor(
    index: int,
) -> CisaKevCanonicalCursor:
    return CisaKevCanonicalCursor(
        cve_id=(
            f"CVE-2026-{1_000 + index}"
        ),
        normalized_record_id=UUID(
            int=index
        ),
    )


def test_rejects_missing_session_factory() -> None:
    with pytest.raises(
        ValueError,
        match="session_factory must not be None",
    ):
        _processor(
            None
        )


def test_rejects_non_callable_session_factory() -> None:
    with pytest.raises(
        TypeError,
        match="session_factory must be callable",
    ):
        _processor(
            object()
        )


def test_rejects_missing_shared_dependencies() -> None:
    factory = cast(
        sessionmaker[Session],
        FakeSessionFactory(),
    )

    with pytest.raises(
        ValueError,
        match="builder must not be None",
    ):
        SqlAlchemyCisaKevCanonicalBatchProcessor(
            session_factory=factory,
            builder=cast(
                CisaKevCanonicalObservationBuilder,
                None,
            ),
            correlation_service=(
                _CORRELATION_SERVICE
            ),
            cwe_enrichment_service=(
                _CWE_ENRICHMENT_SERVICE
            ),
        )

    with pytest.raises(
        ValueError,
        match=(
            "correlation_service "
            "must not be None"
        ),
    ):
        SqlAlchemyCisaKevCanonicalBatchProcessor(
            session_factory=factory,
            builder=_BUILDER,
            correlation_service=cast(
                CanonicalVulnerabilityCorrelationService,
                None,
            ),
            cwe_enrichment_service=(
                _CWE_ENRICHMENT_SERVICE
            ),
        )

    with pytest.raises(
        ValueError,
        match=(
            "cwe_enrichment_service "
            "must not be None"
        ),
    ):
        SqlAlchemyCisaKevCanonicalBatchProcessor(
            session_factory=factory,
            builder=_BUILDER,
            correlation_service=(
                _CORRELATION_SERVICE
            ),
            cwe_enrichment_service=cast(
                CanonicalCWEEnrichmentService,
                None,
            ),
        )


def test_opens_and_closes_a_new_session_per_batch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory = FakeSessionFactory()

    expected_results = [
        cast(
            CisaKevCanonicalCorrelationBatchResult,
            object(),
        ),
        cast(
            CisaKevCanonicalCorrelationBatchResult,
            object(),
        ),
    ]

    source_sessions: list[
        FakeSession
    ] = []

    service_dependencies: list[
        tuple[
            object,
            object,
            object,
            object,
        ]
    ] = []

    process_calls: list[
        tuple[
            CisaKevCanonicalCursor
            | None,
            int,
        ]
    ] = []

    class FakeSource:
        def __init__(
            self,
            *,
            session: FakeSession,
        ) -> None:
            self.session = session

            source_sessions.append(
                session
            )

    class FakeBatchService:
        DEFAULT_BATCH_SIZE = 500

        def __init__(
            self,
            *,
            source: object,
            builder: object,
            correlation_service: object,
            cwe_enrichment_service: object,
        ) -> None:
            service_dependencies.append(
                (
                    source,
                    builder,
                    correlation_service,
                    cwe_enrichment_service,
                )
            )

        def process_batch(
            self,
            *,
            after_cursor: (
                CisaKevCanonicalCursor
                | None
            ),
            limit: int,
        ) -> (
            CisaKevCanonicalCorrelationBatchResult
        ):
            process_calls.append(
                (
                    after_cursor,
                    limit,
                )
            )

            return expected_results[
                len(process_calls) - 1
            ]

    monkeypatch.setattr(
        processor_module,
        "SqlAlchemyCisaKevCanonicalSource",
        FakeSource,
    )

    monkeypatch.setattr(
        processor_module,
        (
            "CisaKevCanonicalCorrelation"
            "BatchService"
        ),
        FakeBatchService,
    )

    processor = _processor(
        factory
    )

    cursor = _cursor(
        1
    )

    first_result = processor.process_batch(
        after_cursor=None,
        limit=100,
    )

    second_result = processor.process_batch(
        after_cursor=cursor,
        limit=200,
    )

    assert first_result is expected_results[0]
    assert second_result is expected_results[1]

    assert len(
        factory.sessions
    ) == 2

    assert (
        factory.sessions[0]
        is not factory.sessions[1]
    )

    assert source_sessions == (
        factory.sessions
    )

    assert [
        session.close_calls
        for session in factory.sessions
    ] == [
        1,
        1,
    ]

    assert process_calls == [
        (
            None,
            100,
        ),
        (
            cursor,
            200,
        ),
    ]

    assert len(
        service_dependencies
    ) == 2

    for (
        source,
        builder,
        correlation_service,
        cwe_enrichment_service,
    ) in service_dependencies:
        assert isinstance(
            source,
            FakeSource,
        )

        assert builder is _BUILDER

        assert (
            correlation_service
            is _CORRELATION_SERVICE
        )

        assert (
            cwe_enrichment_service
            is _CWE_ENRICHMENT_SERVICE
        )

    assert not hasattr(
        processor,
        "_session",
    )


def test_closes_session_when_batch_processing_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    factory = FakeSessionFactory()

    class FakeSource:
        def __init__(
            self,
            *,
            session: FakeSession,
        ) -> None:
            self.session = session

    class FailingBatchService:
        DEFAULT_BATCH_SIZE = 500

        def __init__(
            self,
            **_: object,
        ) -> None:
            pass

        def process_batch(
            self,
            **_: object,
        ) -> (
            CisaKevCanonicalCorrelationBatchResult
        ):
            raise RuntimeError(
                "batch failure"
            )

    monkeypatch.setattr(
        processor_module,
        "SqlAlchemyCisaKevCanonicalSource",
        FakeSource,
    )

    monkeypatch.setattr(
        processor_module,
        (
            "CisaKevCanonicalCorrelation"
            "BatchService"
        ),
        FailingBatchService,
    )

    processor = _processor(
        factory
    )

    with pytest.raises(
        RuntimeError,
        match="batch failure",
    ):
        processor.process_batch(
            limit=50
        )

    assert len(
        factory.sessions
    ) == 1

    assert (
        factory.sessions[0].close_calls
        == 1
    )