from __future__ import annotations

from dotenv import load_dotenv

load_dotenv()

import os
from datetime import date
from uuid import uuid4

import pytest
from sqlalchemy import (
    create_engine,
    delete,
    text,
)
from sqlalchemy.orm import (
    Session,
    sessionmaker,
)

from application.models.epss_snapshot import (
    EPSSSnapshot,
)
from infrastructure.persistence.models.normalized import (
    EPSSScoreModel,
)
from infrastructure.persistence.sqlalchemy import (
    SqlAlchemyUnitOfWork,
    create_ingestion_engine,
    create_session_factory,
)


pytestmark = pytest.mark.integration


def _build_snapshot(
    *,
    score: float,
    percentile: float,
    score_date: date,
    api_version: str | None = "v1",
) -> EPSSSnapshot:
    return EPSSSnapshot(
        score=score,
        percentile=percentile,
        score_date=score_date,
        api_version=api_version,
    )


def test_upsert_and_read_with_real_postgresql() -> None:
    database_url = os.environ.get(
        "MIGRATION_DATABASE_URL"
    )

    if not database_url:
        raise RuntimeError(
            "MIGRATION_DATABASE_URL is not defined"
        )

    serial_number = (
        100_000_000
        + uuid4().int % 900_000_000
    )

    cve_id = (
        f"CVE-2026-{serial_number}"
    )

    owner_engine = create_engine(
        database_url,
        pool_pre_ping=True,
    )

    owner_session_factory = sessionmaker(
        bind=owner_engine,
        class_=Session,
        autoflush=False,
        expire_on_commit=False,
    )

    ingestion_engine = (
        create_ingestion_engine()
    )

    ingestion_session_factory = (
        create_session_factory(
            ingestion_engine
        )
    )

    try:
        unit_of_work = SqlAlchemyUnitOfWork(
            session_factory=(
                ingestion_session_factory
            ),
        )

        initial_snapshot = _build_snapshot(
            score=0.40,
            percentile=0.70,
            score_date=date(
                2026,
                7,
                30,
            ),
            api_version="v1",
        )

        with unit_of_work:
            count = (
                unit_of_work
                .epss_scores
                .upsert_many(
                    {
                        cve_id: initial_snapshot,
                    }
                )
            )

            assert count == 1

            unit_of_work.commit()

        with unit_of_work:
            persisted = (
                unit_of_work
                .epss_scores
                .find_by_cve_id(
                    cve_id
                )
            )

            assert persisted is not None
            assert persisted.score == 0.40
            assert persisted.percentile == 0.70
            assert persisted.score_date == date(
                2026,
                7,
                30,
            )
            assert persisted.api_version == "v1"

        updated_snapshot = _build_snapshot(
            score=0.65,
            percentile=0.85,
            score_date=date(
                2026,
                7,
                30,
            ),
            api_version="v2",
        )

        with unit_of_work:
            count = (
                unit_of_work
                .epss_scores
                .upsert_many(
                    {
                        cve_id: updated_snapshot,
                    }
                )
            )

            assert count == 1

            unit_of_work.commit()

        with unit_of_work:
            updated = (
                unit_of_work
                .epss_scores
                .find_by_cve_id(
                    cve_id
                )
            )

            assert updated is not None
            assert updated.score == 0.65
            assert updated.percentile == 0.85
            assert updated.score_date == date(
                2026,
                7,
                30,
            )
            assert updated.api_version == "v2"

        older_snapshot = _build_snapshot(
            score=0.10,
            percentile=0.20,
            score_date=date(
                2026,
                7,
                29,
            ),
            api_version="old",
        )

        with unit_of_work:
            count = (
                unit_of_work
                .epss_scores
                .upsert_many(
                    {
                        cve_id: older_snapshot,
                    }
                )
            )

            assert count == 1

            unit_of_work.commit()

        with unit_of_work:
            preserved = (
                unit_of_work
                .epss_scores
                .find_by_cve_id(
                    cve_id
                )
            )

            assert preserved is not None

            # Le snapshot plus ancien ne doit pas
            # écraser le snapshot courant.
            assert preserved.score == 0.65
            assert preserved.percentile == 0.85
            assert preserved.score_date == date(
                2026,
                7,
                30,
            )
            assert preserved.api_version == "v2"

        with ingestion_session_factory() as session:
            model = session.get(
                EPSSScoreModel,
                cve_id,
            )

            assert model is not None
            assert model.synchronized_at is not None

    finally:
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
                    == cve_id
                )
            )

            session.commit()

        ingestion_engine.dispose()
        owner_engine.dispose()