from __future__ import annotations

from sqlalchemy.orm import (
    Session,
    sessionmaker,
)

from application.models.urlhaus_canonical_source_record import (
    URLhausCanonicalCursor,
)
from application.services.canonical_web_indicator_correlation_service import (
    CanonicalWebIndicatorCorrelationService,
)
from application.services.urlhaus_canonical_correlation_batch_service import (
    URLhausCanonicalCorrelationBatchResult,
    URLhausCanonicalCorrelationBatchService,
)
from application.services.urlhaus_canonical_observation_builder import (
    URLhausCanonicalObservationBuilder,
)
from infrastructure.persistence.sqlalchemy.readers.urlhaus_canonical_source import (
    SqlAlchemyURLhausCanonicalSource,
)


class SqlAlchemyURLhausCanonicalBatchProcessor:
    """
    Traite un lot canonique URLhaus avec une session
    SQLAlchemy de lecture à durée courte.

    Aucun objet SQLAlchemy n'est conservé entre deux lots.
    """

    def __init__(
        self,
        *,
        session_factory: sessionmaker[Session],
        builder: (
            URLhausCanonicalObservationBuilder
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
            URLhausCanonicalCursor
            | None
        ) = None,
        limit: int = 500,
    ) -> (
        URLhausCanonicalCorrelationBatchResult
    ):
        session = self._session_factory()

        try:
            source = (
                SqlAlchemyURLhausCanonicalSource(
                    session=session,
                )
            )

            service = (
                URLhausCanonicalCorrelationBatchService(
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