from __future__ import annotations

from datetime import timedelta
import os
from pathlib import Path
from uuid import UUID

from dotenv import load_dotenv

from application.services.cisa_kev_normalization_service import (
    CisaKevNormalizationService,
)
from application.services.cisa_kev_normalizer import (
    CisaKevNormalizer,
)
from infrastructure.adapters.inbound.cisa_kev_normalization_job import (
    CisaKevNormalizationJob,
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


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = PROJECT_ROOT / ".env"

load_dotenv(
    dotenv_path=ENV_FILE,
    override=False,
)


CISA_KEV_SOURCE_CODE = "CISA_KEV"

CISA_NORMALIZATION_BATCH_SIZE_ENV = (
    "CISA_NORMALIZATION_BATCH_SIZE"
)
CISA_NORMALIZATION_LEASE_TIMEOUT_SECONDS_ENV = (
    "CISA_NORMALIZATION_LEASE_TIMEOUT_SECONDS"
)
CISA_NORMALIZATION_MAX_ATTEMPTS_ENV = (
    "CISA_NORMALIZATION_MAX_ATTEMPTS"
)

DEFAULT_BATCH_SIZE = 100
DEFAULT_LEASE_TIMEOUT_SECONDS = 900
DEFAULT_MAX_ATTEMPTS = 3


def build_cisa_kev_normalization_job(
    *,
    source_id: UUID,
) -> CisaKevNormalizationJob:
    """
    Assemble le pipeline de normalisation CISA KEV.

    Composition :

    PostgreSQL engine
    -> session factory
    -> Unit of Work
    -> CISA normalizer
    -> normalization service
    -> normalization job

    La configuration est validée avant la création des
    connexions et dépendances de persistance.
    """

    if not isinstance(source_id, UUID):
        raise TypeError(
            "source_id must be a UUID"
        )

    batch_size = _read_positive_integer(
        variable_name=(
            CISA_NORMALIZATION_BATCH_SIZE_ENV
        ),
        default=DEFAULT_BATCH_SIZE,
    )

    lease_timeout_seconds = _read_positive_integer(
        variable_name=(
            CISA_NORMALIZATION_LEASE_TIMEOUT_SECONDS_ENV
        ),
        default=DEFAULT_LEASE_TIMEOUT_SECONDS,
    )

    max_attempts = _read_positive_integer(
        variable_name=(
            CISA_NORMALIZATION_MAX_ATTEMPTS_ENV
        ),
        default=DEFAULT_MAX_ATTEMPTS,
    )

    engine = create_ingestion_engine()

    session_factory = create_session_factory(
        engine
    )

    unit_of_work = SqlAlchemyUnitOfWork(
        session_factory=session_factory,
    )

    normalizer = CisaKevNormalizer()

    normalization_service = (
        CisaKevNormalizationService(
            unit_of_work=unit_of_work,
            normalizer=normalizer,
            lease_timeout=timedelta(
                seconds=lease_timeout_seconds
            ),
            max_attempts=max_attempts,
        )
    )

    return CisaKevNormalizationJob(
        normalization_service=(
            normalization_service
        ),
        source_id=source_id,
        source_code=CISA_KEV_SOURCE_CODE,
        batch_size=batch_size,
    )


def _read_positive_integer(
    *,
    variable_name: str,
    default: int,
) -> int:
    """
    Lit une variable d'environnement entière et positive.

    Une variable absente utilise la valeur par défaut.

    Une variable présente mais vide, non numérique ou non
    positive est considérée comme une erreur de configuration.
    Le démarrage échoue alors immédiatement afin d'éviter un
    comportement silencieux ou une boucle de traitement
    incorrectement configurée.
    """

    raw_value = os.environ.get(variable_name)

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
            f"{variable_name} must be greater than zero"
        )

    return parsed_value