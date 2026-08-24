from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)

load_dotenv(
    dotenv_path=(
        PROJECT_ROOT / ".env"
    ),
    override=False,
)


from application.services.canonical_cwe_association_builder import (
    CanonicalCWEAssociationBuilder,
)
from application.services.canonical_cwe_enrichment_service import (
    CanonicalCWEEnrichmentService,
)
from application.services.canonical_vulnerability_correlation_service import (
    CanonicalVulnerabilityCorrelationService,
)
from application.services.cwe_lookup_service import (
    CWELookupService,
)
from application.services.github_advisory_canonical_observation_builder import (
    GitHubAdvisoryCanonicalObservationBuilder,
)
from infrastructure.adapters.inbound.github_advisory_canonical_correlation_job import (
    GitHubAdvisoryCanonicalCorrelationJob,
)
from infrastructure.persistence.sqlalchemy.engine import (
    create_ingestion_engine,
)
from infrastructure.persistence.sqlalchemy.processors.github_advisory_canonical_batch_processor import (
    SqlAlchemyGitHubAdvisoryCanonicalBatchProcessor,
)
from infrastructure.persistence.sqlalchemy.session import (
    create_session_factory,
)
from infrastructure.persistence.sqlalchemy.unit_of_work import (
    SqlAlchemyUnitOfWork,
)


GITHUB_ADVISORY_CANONICAL_BATCH_SIZE_ENV = (
    "GITHUB_ADVISORY_CANONICAL_BATCH_SIZE"
)

GITHUB_ADVISORY_CANONICAL_MAX_BATCHES_ENV = (
    "GITHUB_ADVISORY_CANONICAL_MAX_BATCHES"
)


DEFAULT_BATCH_SIZE = 500
DEFAULT_MAX_BATCHES = 10_000

MAX_ALLOWED_BATCH_SIZE = 1_000
MAX_ALLOWED_MAX_BATCHES = 100_000


def build_github_advisory_canonical_correlation_job(
    *,
    incremental_only: bool = False,
) -> GitHubAdvisoryCanonicalCorrelationJob:
    """
    Assemble le pipeline canonique GitHub Advisory.

    incremental_only=False :
        comportement historique / backfill complet.

    incremental_only=True :
        comportement scheduler. Seuls les advisories
        nouveaux ou dont la version normalisée a changé
        sont proposés à la canonicalisation.

    La configuration est intégralement validée avant
    la création du pool PostgreSQL.
    """

    if not isinstance(
        incremental_only,
        bool,
    ):
        raise TypeError(
            "incremental_only must be a boolean"
        )

    batch_size = (
        _read_bounded_positive_integer(
            variable_name=(
                GITHUB_ADVISORY_CANONICAL_BATCH_SIZE_ENV
            ),
            default=DEFAULT_BATCH_SIZE,
            maximum=MAX_ALLOWED_BATCH_SIZE,
        )
    )

    max_batches = (
        _read_bounded_positive_integer(
            variable_name=(
                GITHUB_ADVISORY_CANONICAL_MAX_BATCHES_ENV
            ),
            default=DEFAULT_MAX_BATCHES,
            maximum=MAX_ALLOWED_MAX_BATCHES,
        )
    )

    engine = (
        create_ingestion_engine()
    )

    session_factory = (
        create_session_factory(
            engine
        )
    )

    correlation_unit_of_work = (
        SqlAlchemyUnitOfWork(
            session_factory=(
                session_factory
            ),
        )
    )

    cwe_lookup_unit_of_work = (
        SqlAlchemyUnitOfWork(
            session_factory=(
                session_factory
            ),
        )
    )

    cwe_enrichment_unit_of_work = (
        SqlAlchemyUnitOfWork(
            session_factory=(
                session_factory
            ),
        )
    )

    correlation_service = (
        CanonicalVulnerabilityCorrelationService(
            unit_of_work=(
                correlation_unit_of_work
            ),
            max_observations=(
                batch_size
            ),
        )
    )

    cwe_lookup_service = (
        CWELookupService(
            unit_of_work=(
                cwe_lookup_unit_of_work
            ),
        )
    )

    association_builder = (
        CanonicalCWEAssociationBuilder()
    )

    cwe_enrichment_service = (
        CanonicalCWEEnrichmentService(
            unit_of_work=(
                cwe_enrichment_unit_of_work
            ),
            cwe_lookup=(
                cwe_lookup_service
            ),
            builder=(
                association_builder
            ),
            max_records=(
                batch_size
            ),
        )
    )

    observation_builder = (
        GitHubAdvisoryCanonicalObservationBuilder()
    )

    processor = (
        SqlAlchemyGitHubAdvisoryCanonicalBatchProcessor(
            session_factory=(
                session_factory
            ),
            builder=(
                observation_builder
            ),
            correlation_service=(
                correlation_service
            ),
            cwe_enrichment_service=(
                cwe_enrichment_service
            ),
            incremental_only=(
                incremental_only
            ),
        )
    )

    return (
        GitHubAdvisoryCanonicalCorrelationJob(
            processor=processor,
            batch_size=batch_size,
            max_batches=max_batches,
        )
    )


def _read_bounded_positive_integer(
    *,
    variable_name: str,
    default: int,
    maximum: int,
) -> int:
    raw_value = os.environ.get(
        variable_name
    )

    if raw_value is None:
        return default

    normalized_value = (
        raw_value.strip()
    )

    if not normalized_value:
        raise RuntimeError(
            f"{variable_name} must not be empty"
        )

    try:
        parsed_value = int(
            normalized_value
        )

    except ValueError as error:
        raise RuntimeError(
            f"{variable_name} must be an integer"
        ) from error

    if parsed_value < 1:
        raise RuntimeError(
            f"{variable_name} must be "
            "greater than zero"
        )

    if parsed_value > maximum:
        raise RuntimeError(
            f"{variable_name} must not exceed "
            f"{maximum}"
        )

    return parsed_value