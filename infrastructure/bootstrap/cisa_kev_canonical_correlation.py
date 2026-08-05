from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[2]

load_dotenv(
    dotenv_path=PROJECT_ROOT / ".env",
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
from application.services.cisa_kev_canonical_observation_builder import (
    CisaKevCanonicalObservationBuilder,
)
from application.services.cwe_lookup_service import (
    CWELookupService,
)
from infrastructure.adapters.inbound.cisa_kev_canonical_correlation_job import (
    CisaKevCanonicalCorrelationJob,
)
from infrastructure.persistence.sqlalchemy.engine import (
    create_ingestion_engine,
)
from infrastructure.persistence.sqlalchemy.processors.cisa_kev_canonical_batch_processor import (
    SqlAlchemyCisaKevCanonicalBatchProcessor,
)
from infrastructure.persistence.sqlalchemy.session import (
    create_session_factory,
)
from infrastructure.persistence.sqlalchemy.unit_of_work import (
    SqlAlchemyUnitOfWork,
)


CISA_KEV_CANONICAL_BATCH_SIZE_ENV = (
    "CISA_KEV_CANONICAL_BATCH_SIZE"
)

CISA_KEV_CANONICAL_MAX_BATCHES_ENV = (
    "CISA_KEV_CANONICAL_MAX_BATCHES"
)

DEFAULT_BATCH_SIZE = 500
DEFAULT_MAX_BATCHES = 10_000

MAX_ALLOWED_BATCH_SIZE = 1_000
MAX_ALLOWED_MAX_BATCHES = 100_000


def build_cisa_kev_canonical_correlation_job(
) -> CisaKevCanonicalCorrelationJob:
    """
    Assemble le pipeline canonique CISA KEV.

    La configuration est intégralement validée avant
    la création du pool PostgreSQL.

    Un seul engine et une seule session_factory sont créés.
    Les différents Unit of Work partagent la factory, mais
    ouvrent des sessions et transactions indépendantes.
    """

    batch_size = _read_bounded_positive_integer(
        variable_name=(
            CISA_KEV_CANONICAL_BATCH_SIZE_ENV
        ),
        default=DEFAULT_BATCH_SIZE,
        maximum=MAX_ALLOWED_BATCH_SIZE,
    )

    max_batches = _read_bounded_positive_integer(
        variable_name=(
            CISA_KEV_CANONICAL_MAX_BATCHES_ENV
        ),
        default=DEFAULT_MAX_BATCHES,
        maximum=MAX_ALLOWED_MAX_BATCHES,
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

    cwe_lookup_unit_of_work = (
        SqlAlchemyUnitOfWork(
            session_factory=session_factory,
        )
    )

    cwe_enrichment_unit_of_work = (
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

    cwe_lookup_service = CWELookupService(
        unit_of_work=cwe_lookup_unit_of_work,
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
            max_records=batch_size,
        )
    )

    observation_builder = (
        CisaKevCanonicalObservationBuilder()
    )

    processor = (
        SqlAlchemyCisaKevCanonicalBatchProcessor(
            session_factory=session_factory,
            builder=observation_builder,
            correlation_service=(
                correlation_service
            ),
            cwe_enrichment_service=(
                cwe_enrichment_service
            ),
        )
    )

    return CisaKevCanonicalCorrelationJob(
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
    Lit une variable entière strictement positive et bornée.

    Une variable absente utilise la valeur par défaut.
    Une variable présente mais vide ou invalide provoque
    un échec immédiat avant toute connexion PostgreSQL.
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