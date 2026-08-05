from __future__ import annotations

from sqlalchemy.orm import (
    Session,
    sessionmaker,
)

from application.models.github_advisory_canonical_source_record import (
    GitHubAdvisoryCanonicalCursor,
)
from application.services.canonical_cwe_enrichment_service import (
    CanonicalCWEEnrichmentService,
)
from application.services.canonical_vulnerability_correlation_service import (
    CanonicalVulnerabilityCorrelationService,
)
from application.services.github_advisory_canonical_correlation_batch_service import (
    GitHubAdvisoryCanonicalCorrelationBatchResult,
    GitHubAdvisoryCanonicalCorrelationBatchService,
)
from application.services.github_advisory_canonical_observation_builder import (
    GitHubAdvisoryCanonicalObservationBuilder,
)
from infrastructure.persistence.sqlalchemy.readers.github_advisory_canonical_source import (
    SqlAlchemyGitHubAdvisoryCanonicalSource,
)


class SqlAlchemyGitHubAdvisoryCanonicalBatchProcessor:
    """
    Traite un seul lot canonique GitHub Advisory avec
    une session SQLAlchemy de lecture à durée courte.

    La session n'est jamais conservée dans l'instance.
    Les écritures canoniques restent gérées par les Unit
    of Work injectées dans les services applicatifs.
    """

    def __init__(
        self,
        *,
        session_factory: sessionmaker[Session],
        builder: GitHubAdvisoryCanonicalObservationBuilder,
        correlation_service: (
            CanonicalVulnerabilityCorrelationService
        ),
        cwe_enrichment_service: (
            CanonicalCWEEnrichmentService
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

        if cwe_enrichment_service is None:
            raise ValueError(
                "cwe_enrichment_service "
                "must not be None"
            )

        self._session_factory = (
            session_factory
        )
        self._builder = builder
        self._correlation_service = (
            correlation_service
        )
        self._cwe_enrichment_service = (
            cwe_enrichment_service
        )

    def process_batch(
        self,
        *,
        after_cursor: (
            GitHubAdvisoryCanonicalCursor
            | None
        ) = None,
        limit: int = (
            GitHubAdvisoryCanonicalCorrelationBatchService
            .DEFAULT_BATCH_SIZE
        ),
    ) -> (
        GitHubAdvisoryCanonicalCorrelationBatchResult
    ):
        session = self._session_factory()

        try:
            source = (
                SqlAlchemyGitHubAdvisoryCanonicalSource(
                    session=session,
                )
            )

            batch_service = (
                GitHubAdvisoryCanonicalCorrelationBatchService(
                    source=source,
                    builder=self._builder,
                    correlation_service=(
                        self._correlation_service
                    ),
                    cwe_enrichment_service=(
                        self._cwe_enrichment_service
                    ),
                )
            )

            return batch_service.process_batch(
                after_cursor=after_cursor,
                limit=limit,
            )

        finally:
            session.close()