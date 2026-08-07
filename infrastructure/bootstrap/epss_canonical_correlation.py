from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(
    __file__
).resolve().parents[2]

load_dotenv(
    dotenv_path=PROJECT_ROOT / ".env",
    override=False,
)


from application.services.canonical_epss_enrichment_service import (
    CanonicalEPSSEnrichmentService,
)
from application.services.canonical_vulnerability_correlation_service import (
    CanonicalVulnerabilityCorrelationService,
)
from application.services.epss_canonical_observation_builder import (
    EPSSCanonicalObservationBuilder,
)
from infrastructure.adapters.inbound.epss_canonical_correlation_job import (
    EPSSCanonicalCorrelationJob,
)
from infrastructure.persistence.sqlalchemy.engine import (
    create_ingestion_engine,
)
from infrastructure.persistence.sqlalchemy.processors.epss_canonical_batch_processor import (
    SqlAlchemyEPSSCanonicalBatchProcessor,
)
from infrastructure.persistence.sqlalchemy.session import (
    create_session_factory,
)
from infrastructure.persistence.sqlalchemy.unit_of_work import (
    SqlAlchemyUnitOfWork,
)


EPSS_CANONICAL_BATCH_SIZE_ENV = (
    "EPSS_CANONICAL_BATCH_SIZE"
)

EPSS_CANONICAL_MAX_BATCHES_ENV = (
    "EPSS_CANONICAL_MAX_BATCHES"
)

DEFAULT_BATCH_SIZE = 500
DEFAULT_MAX_BATCHES = 10_000

MAX_ALLOWED_BATCH_SIZE = 1_000
MAX_ALLOWED_MAX_BATCHES = 100_000


def build_epss_canonical_correlation_job(
) -> EPSSCanonicalCorrelationJob:
    """
    Assemble le pipeline EPSS complet :

        normalized.epss_score
        -> corrélation canonique par CVE
        -> création éventuelle d'une CVE provisoire
        -> persistance du snapshot EPSS courant
    """

    batch_size = (
        _read_bounded_positive_integer(
            variable_name=(
                EPSS_CANONICAL_BATCH_SIZE_ENV
            ),
            default=DEFAULT_BATCH_SIZE,
            maximum=MAX_ALLOWED_BATCH_SIZE,
        )
    )

    max_batches = (
        _read_bounded_positive_integer(
            variable_name=(
                EPSS_CANONICAL_MAX_BATCHES_ENV
            ),
            default=DEFAULT_MAX_BATCHES,
            maximum=MAX_ALLOWED_MAX_BATCHES,
        )
    )

    engine = create_ingestion_engine()

    session_factory = create_session_factory(
        engine
    )

    correlation_unit_of_work = (
        SqlAlchemyUnitOfWork(
            session_factory=session_factory,
        )
    )

    epss_enrichment_unit_of_work = (
        SqlAlchemyUnitOfWork(
            session_factory=session_factory,
        )
    )

    correlation_service = (
        CanonicalVulnerabilityCorrelationService(
            unit_of_work=(
                correlation_unit_of_work
            ),
            max_observations=batch_size,
        )
    )

    epss_enrichment_service = (
        CanonicalEPSSEnrichmentService(
            unit_of_work=(
                epss_enrichment_unit_of_work
            ),
            max_records=batch_size,
        )
    )

    observation_builder = (
        EPSSCanonicalObservationBuilder()
    )

    processor = (
        SqlAlchemyEPSSCanonicalBatchProcessor(
            session_factory=session_factory,
            builder=observation_builder,
            correlation_service=(
                correlation_service
            ),
            epss_enrichment_service=(
                epss_enrichment_service
            ),
        )
    )

    return EPSSCanonicalCorrelationJob(
        processor=processor,
        batch_size=batch_size,
        max_batches=max_batches,
    )


def _read_bounded_positive_integer(
    *,
    variable_name: str,
    default: int,
    maximum: int,
) -> int:
    """
    Lit une variable entière strictement positive
    et bornée.

    La configuration est validée avant l'ouverture
    du pool PostgreSQL.
    """

    raw_value = os.environ.get(
        variable_name
    )

    if raw_value is None:
        return default

    normalized_value = raw_value.strip()

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