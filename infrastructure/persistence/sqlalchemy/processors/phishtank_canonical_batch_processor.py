from __future__ import annotations

from sqlalchemy.orm import (
    Session,
    sessionmaker,
)

from application.models.phishtank_canonical_source_record import (
    PhishTankCanonicalCursor,
)
from application.services.canonical_web_indicator_correlation_service import (
    CanonicalWebIndicatorCorrelationService,
)
from application.services.phishtank_canonical_correlation_batch_service import (
    PhishTankCanonicalCorrelationBatchResult,
    PhishTankCanonicalCorrelationBatchService,
)
from application.services.phishtank_canonical_observation_builder import (
    PhishTankCanonicalObservationBuilder,
)
from infrastructure.persistence.sqlalchemy.readers.phishtank_canonical_source import (
    SqlAlchemyPhishTankCanonicalSource,
)


class SqlAlchemyPhishTankCanonicalBatchProcessor:
    """
    Traite un lot canonique PhishTank avec une session
    SQLAlchemy de lecture à durée courte.

    Les écritures canoniques utilisent leur propre Unit of Work
    à travers le service de corrélation injecté.
    """

    def __init__(
        self,
        *,
        session_factory: sessionmaker[Session],
        builder: (
            PhishTankCanonicalObservationBuilder
        ),
        correlation_service: (
            CanonicalWebIndicatorCorrelationService
        ),
    ) -> None:
        if session_factory is None:
            raise ValueError(
                "session_factory must not be None"
            )

        if not callable(
            session_factory
        ):
            raise TypeError(
                "session_factory must be callable"
            )

        if builder is None:
            raise ValueError(
                "builder must not be None"
            )

        if correlation_service is None:
            raise ValueError(
                "correlation_service must not be None"
            )

        self._session_factory = (
            session_factory
        )

        self._builder = builder

        self._correlation_service = (
            correlation_service
        )

    def process_batch(
        self,
        *,
        after_cursor: (
            PhishTankCanonicalCursor
            | None
        ) = None,
        limit: int = 500,
    ) -> (
        PhishTankCanonicalCorrelationBatchResult
    ):
        session = self._session_factory()

        try:
            source = (
                SqlAlchemyPhishTankCanonicalSource(
                    session=session,
                )
            )

            service = (
                PhishTankCanonicalCorrelationBatchService(
                    source=source,
                    builder=self._builder,
                    correlation_service=(
                        self._correlation_service
                    ),
                )
            )

            return service.process_batch(
                after_cursor=after_cursor,
                limit=limit,
            )

        finally:
            session.close()