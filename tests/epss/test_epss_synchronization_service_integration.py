from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv

# Charger les variables avant les imports susceptibles
# d'utiliser la configuration PostgreSQL.
load_dotenv(
    dotenv_path=Path.cwd() / ".env",
    override=False,
)

import os
from datetime import date

import pytest
from sqlalchemy import (
    create_engine,
    delete,
    select,
    text,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import (
    Session,
    sessionmaker,
)

from application.services.epss_synchronization_service import (
    EPSSSynchronizationService,
)
from infrastructure.adapters.outbound.epss_connector import (
    EPSSConnector,
)
from infrastructure.persistence.models.normalized import (
    EPSSScoreModel,
)
from infrastructure.persistence.sqlalchemy import (
    SqlAlchemyUnitOfWork,
    create_ingestion_engine,
    create_session_factory,
)


pytestmark = [
    pytest.mark.integration,
    pytest.mark.external,
]


# Plusieurs CVE connus permettent d'éviter d'écraser une ligne
# déjà présente dans une base de développement partagée.
KNOWN_CVE_IDS: tuple[str, ...] = (
    "CVE-2021-44228",
    "CVE-2023-23397",
    "CVE-2024-3094",
    "CVE-2017-0144",
)


def _create_owner_session_factory(
) -> tuple[
    sessionmaker[Session],
    Engine,
]:
    database_url = os.environ.get(
        "MIGRATION_DATABASE_URL"
    )

    if not database_url:
        raise RuntimeError(
            "MIGRATION_DATABASE_URL is not defined"
        )

    engine = create_engine(
        database_url,
        pool_pre_ping=True,
    )

    factory = sessionmaker(
        bind=engine,
        class_=Session,
        autoflush=False,
        expire_on_commit=False,
    )

    return factory, engine


def _select_available_cve(
    owner_session_factory: sessionmaker[Session],
) -> str:
    """
    Sélectionne un CVE qui n'est pas déjà présent.

    Le test ne doit jamais écraser puis supprimer une vraie donnée
    préexistante dans une base partagée.
    """
    with owner_session_factory() as session:
        session.execute(
            text(
                "SET ROLE threat_intel_owner"
            )
        )

        statement = (
            select(
                EPSSScoreModel.cve_id
            )
            .where(
                EPSSScoreModel.cve_id.in_(
                    KNOWN_CVE_IDS
                )
            )
        )

        existing_cve_ids = set(
            session.execute(
                statement
            )
            .scalars()
            .all()
        )

    for cve_id in KNOWN_CVE_IDS:
        if cve_id not in existing_cve_ids:
            return cve_id

    pytest.skip(
        "All EPSS integration test CVEs already exist "
        "in normalized.epss_score; refusing to overwrite "
        "pre-existing data."
    )


def test_synchronize_first_score_with_real_postgresql(
) -> None:
    owner_session_factory, owner_engine = (
        _create_owner_session_factory()
    )

    ingestion_engine = create_ingestion_engine()

    ingestion_session_factory = (
        create_session_factory(
            ingestion_engine
        )
    )

    test_cve_id: str | None = None

    try:
        test_cve_id = _select_available_cve(
            owner_session_factory
        )

        # ==========================================================
        # Exécution du flux réel
        #
        # FIRST API
        #   -> EPSSConnector
        #   -> EPSSSynchronizationService
        #   -> SqlAlchemyUnitOfWork
        #   -> normalized.epss_score
        # ==========================================================

        unit_of_work = SqlAlchemyUnitOfWork(
            session_factory=(
                ingestion_session_factory
            )
        )

        with EPSSConnector() as provider:
            service = EPSSSynchronizationService(
                provider=provider,
                unit_of_work=unit_of_work,
            )

            result = service.synchronize(
                [test_cve_id]
            )

        # ==========================================================
        # Validation du résultat applicatif
        # ==========================================================

        assert result.requested_cves == 1
        assert result.fetched_scores == 1
        assert result.submitted_scores == 1
        assert not result.missing_cves
        assert result.requested_score_date is None

        # ==========================================================
        # Relecture via le repository du Unit of Work
        # ==========================================================

        with SqlAlchemyUnitOfWork(
            session_factory=(
                ingestion_session_factory
            )
        ) as verification_uow:
            snapshot = (
                verification_uow
                .epss_scores
                .find_by_cve_id(
                    test_cve_id
                )
            )

        assert snapshot is not None
        assert isinstance(
            snapshot.score_date,
            date,
        )

        assert 0.0 <= snapshot.score <= 1.0
        assert 0.0 <= snapshot.percentile <= 1.0

        # ==========================================================
        # Validation directe de la ligne PostgreSQL
        # ==========================================================

        with ingestion_session_factory() as session:
            stored_model = session.get(
                EPSSScoreModel,
                test_cve_id,
            )

            assert stored_model is not None

            assert stored_model.cve_id == (
                test_cve_id
            )

            assert stored_model.epss_score == (
                pytest.approx(
                    snapshot.score
                )
            )

            assert stored_model.percentile == (
                pytest.approx(
                    snapshot.percentile
                )
            )

            assert stored_model.score_date == (
                snapshot.score_date
            )

            assert stored_model.api_version == (
                snapshot.api_version
            )

            assert (
                stored_model.synchronized_at
                is not None
            )

            assert (
                stored_model
                .synchronized_at
                .tzinfo
                is not None
            )

    finally:
        # Le nettoyage utilise volontairement le rôle propriétaire :
        # le rôle ingestion ne possède pas DELETE.
        if test_cve_id is not None:
            with owner_session_factory() as session:
                session.execute(
                    text(
                        "SET ROLE threat_intel_owner"
                    )
                )

                session.execute(
                    delete(
                        EPSSScoreModel
                    ).where(
                        EPSSScoreModel.cve_id
                        == test_cve_id
                    )
                )

                session.commit()

        ingestion_engine.dispose()
        owner_engine.dispose()