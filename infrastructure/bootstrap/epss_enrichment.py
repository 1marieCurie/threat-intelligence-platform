from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = PROJECT_ROOT / ".env"

load_dotenv(
    dotenv_path=ENV_FILE,
    override=False,
)


import os

from application.services.epss_enrichment_service import (
    EPSSEnrichmentService,
)
from application.services.epss_lookup_service import (
    EPSSLookupService,
)
from infrastructure.persistence.sqlalchemy.engine import (
    create_ingestion_engine,
)
from infrastructure.persistence.sqlalchemy.session import (
    create_session_factory,
)
from infrastructure.persistence.sqlalchemy.unit_of_work import (
    SqlAlchemyUnitOfWork,
)


EPSS_ENRICHMENT_MAX_CVE_IDS_ENV = (
    "EPSS_ENRICHMENT_MAX_CVE_IDS"
)

DEFAULT_MAX_CVE_IDS = 50_000
MAX_ALLOWED_CVE_IDS = 50_000


def build_epss_enrichment_service(
) -> EPSSEnrichmentService:
    """
    Construit le service historique d'enrichissement
    EPSS et son lookup local.

    Aucun connecteur HTTP FIRST n'est créé ici.

    Flux :

    EPSSEnrichmentService
        -> EPSSLookupService
        -> SqlAlchemyUnitOfWork
        -> EPSSScoreRepository
        -> normalized.epss_score
    """
    max_cve_ids = _read_positive_integer(
        variable_name=(
            EPSS_ENRICHMENT_MAX_CVE_IDS_ENV
        ),
        default=DEFAULT_MAX_CVE_IDS,
    )

    if max_cve_ids > MAX_ALLOWED_CVE_IDS:
        raise RuntimeError(
            f"{EPSS_ENRICHMENT_MAX_CVE_IDS_ENV} "
            "must not exceed "
            f"{MAX_ALLOWED_CVE_IDS}"
        )

    # La configuration est validée avant la création
    # du pool de connexions PostgreSQL.
    engine = create_ingestion_engine()

    session_factory = create_session_factory(
        engine
    )

    unit_of_work = SqlAlchemyUnitOfWork(
        session_factory=session_factory,
    )

    epss_lookup = EPSSLookupService(
        unit_of_work=unit_of_work,
        max_cve_ids=max_cve_ids,
    )

    return EPSSEnrichmentService(
        epss_lookup=epss_lookup,
    )


def _read_positive_integer(
    *,
    variable_name: str,
    default: int,
) -> int:
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

    return parsed_value