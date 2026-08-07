from __future__ import annotations

from sqlalchemy.orm import (
    Session,
    sessionmaker,
)

from application.services.canonical_epss_enrichment_service import (
    CanonicalEPSSEnrichmentService,
)
from application.services.canonical_vulnerability_correlation_service import (
    CanonicalVulnerabilityCorrelationService,
)
from application.services.epss_canonical_correlation_batch_service import (
    EPSSCanonicalCorrelationBatchResult,
    EPSSCanonicalCorrelationBatchService,
)
from application.services.epss_canonical_observation_builder import (
    EPSSCanonicalObservationBuilder,
)
from infrastructure.persistence.sqlalchemy.readers.epss_canonical_source import (
    SqlAlchemyEPSSCanonicalSource,
)


class SqlAlchemyEPSSCanonicalBatchProcessor:
    """
    Traite un lot EPSS avec une session SQLAlchemy
    de lecture courte.

    Les écritures canoniques sont gérées par les
    Unit of Work injectées dans les services.
    """

    def __init__(
        self,
        *,
        session_factory: sessionmaker[Session],
        builder: EPSSCanonicalObservationBuilder,
        correlation_service: (
            CanonicalVulnerabilityCorrelationService
        ),
        epss_enrichment_service: (
            CanonicalEPSSEnrichmentService
        ),
    ) -> None:
        if session_factory is None:
            raise ValueError(
                "session_factory must not be None"
            )

        if not callable(session_factory):
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

        if epss_enrichment_service is None:
            raise ValueError(
                "epss_enrichment_service "
                "must not be None"
            )

        self._session_factory = session_factory
        self._builder = builder

        self._correlation_service = (
            correlation_service
        )

        self._epss_enrichment_service = (
            epss_enrichment_service
        )

    def process_batch(
        self,
        *,
        after_cve_id: str | None = None,
        limit: int = (
            EPSSCanonicalCorrelationBatchService
            .DEFAULT_BATCH_SIZE
        ),
    ) -> EPSSCanonicalCorrelationBatchResult:
        session = self._session_factory()

        try:
            source = SqlAlchemyEPSSCanonicalSource(
                session=session,
            )

            service = (
                EPSSCanonicalCorrelationBatchService(
                    source=source,
                    builder=self._builder,
                    correlation_service=(
                        self._correlation_service
                    ),
                    epss_enrichment_service=(
                        self._epss_enrichment_service
                    ),
                )
            )

            return service.process_batch(
                after_cve_id=after_cve_id,
                limit=limit,
            )

        finally:
            session.close()