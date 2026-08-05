from __future__ import annotations

from typing import cast
from unittest.mock import Mock

import pytest
from sqlalchemy.orm import (
    Session,
    sessionmaker,
)

from application.ports.outbound.phishtank_canonical_source import (
    PhishTankCanonicalSource,
)
from application.ports.outbound.urlhaus_canonical_source import (
    URLhausCanonicalSource,
)
from application.services.canonical_web_indicator_correlation_service import (
    CanonicalWebIndicatorCorrelationService,
)
from application.services.phishtank_canonical_correlation_batch_service import (
    PhishTankCanonicalCorrelationBatchResult,
)
from application.services.phishtank_canonical_observation_builder import (
    PhishTankCanonicalObservationBuilder,
)
from application.services.urlhaus_canonical_correlation_batch_service import (
    URLhausCanonicalCorrelationBatchResult,
)
from application.services.urlhaus_canonical_observation_builder import (
    URLhausCanonicalObservationBuilder,
)
import infrastructure.persistence.sqlalchemy.processors.phishtank_canonical_batch_processor as phishtank_module
import infrastructure.persistence.sqlalchemy.processors.urlhaus_canonical_batch_processor as urlhaus_module


PHISHTANK_RESULT = cast(
    PhishTankCanonicalCorrelationBatchResult,
    object(),
)

URLHAUS_RESULT = cast(
    URLhausCanonicalCorrelationBatchResult,
    object(),
)


class FakePhishTankSource:
    def __init__(
        self,
        *,
        session: Session,
    ) -> None:
        self.session = session


class FakeURLhausSource:
    def __init__(
        self,
        *,
        session: Session,
    ) -> None:
        self.session = session


class FakePhishTankBatchService:
    def __init__(
        self,
        *,
        source: PhishTankCanonicalSource,
        builder: (
            PhishTankCanonicalObservationBuilder
        ),
        correlation_service: (
            CanonicalWebIndicatorCorrelationService
        ),
    ) -> None:
        del source
        del builder
        del correlation_service

    def process_batch(
        self,
        *,
        after_cursor: object = None,
        limit: int = 500,
    ) -> (
        PhishTankCanonicalCorrelationBatchResult
    ):
        del after_cursor
        del limit

        return PHISHTANK_RESULT


class FakeURLhausBatchService:
    def __init__(
        self,
        *,
        source: URLhausCanonicalSource,
        builder: (
            URLhausCanonicalObservationBuilder
        ),
        correlation_service: (
            CanonicalWebIndicatorCorrelationService
        ),
    ) -> None:
        del source
        del builder
        del correlation_service

    def process_batch(
        self,
        *,
        after_cursor: object = None,
        limit: int = 500,
    ) -> (
        URLhausCanonicalCorrelationBatchResult
    ):
        del after_cursor
        del limit

        return URLHAUS_RESULT


class FailingPhishTankBatchService(
    FakePhishTankBatchService
):
    def process_batch(
        self,
        *,
        after_cursor: object = None,
        limit: int = 500,
    ) -> (
        PhishTankCanonicalCorrelationBatchResult
    ):
        del after_cursor
        del limit

        raise RuntimeError(
            "batch failed"
        )


def _session_factory(
    session: Session,
) -> sessionmaker[Session]:
    return cast(
        sessionmaker[Session],
        lambda: session,
    )


def _correlation_service(
) -> CanonicalWebIndicatorCorrelationService:
    return cast(
        CanonicalWebIndicatorCorrelationService,
        object(),
    )


def test_phishtank_processor_closes_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = Mock(
        spec=Session
    )

    monkeypatch.setattr(
        phishtank_module,
        "SqlAlchemyPhishTankCanonicalSource",
        FakePhishTankSource,
    )

    monkeypatch.setattr(
        phishtank_module,
        (
            "PhishTankCanonicalCorrelation"
            "BatchService"
        ),
        FakePhishTankBatchService,
    )

    processor = (
        phishtank_module
        .SqlAlchemyPhishTankCanonicalBatchProcessor(
            session_factory=(
                _session_factory(
                    session
                )
            ),
            builder=(
                PhishTankCanonicalObservationBuilder()
            ),
            correlation_service=(
                _correlation_service()
            ),
        )
    )

    result = processor.process_batch()

    assert result is PHISHTANK_RESULT

    session.close.assert_called_once_with()


def test_urlhaus_processor_closes_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = Mock(
        spec=Session
    )

    monkeypatch.setattr(
        urlhaus_module,
        "SqlAlchemyURLhausCanonicalSource",
        FakeURLhausSource,
    )

    monkeypatch.setattr(
        urlhaus_module,
        (
            "URLhausCanonicalCorrelation"
            "BatchService"
        ),
        FakeURLhausBatchService,
    )

    processor = (
        urlhaus_module
        .SqlAlchemyURLhausCanonicalBatchProcessor(
            session_factory=(
                _session_factory(
                    session
                )
            ),
            builder=(
                URLhausCanonicalObservationBuilder()
            ),
            correlation_service=(
                _correlation_service()
            ),
        )
    )

    result = processor.process_batch()

    assert result is URLHAUS_RESULT

    session.close.assert_called_once_with()


def test_processor_closes_session_after_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = Mock(
        spec=Session
    )

    monkeypatch.setattr(
        phishtank_module,
        "SqlAlchemyPhishTankCanonicalSource",
        FakePhishTankSource,
    )

    monkeypatch.setattr(
        phishtank_module,
        (
            "PhishTankCanonicalCorrelation"
            "BatchService"
        ),
        FailingPhishTankBatchService,
    )

    processor = (
        phishtank_module
        .SqlAlchemyPhishTankCanonicalBatchProcessor(
            session_factory=(
                _session_factory(
                    session
                )
            ),
            builder=(
                PhishTankCanonicalObservationBuilder()
            ),
            correlation_service=(
                _correlation_service()
            ),
        )
    )

    with pytest.raises(
        RuntimeError,
        match="batch failed",
    ):
        processor.process_batch()

    session.close.assert_called_once_with()