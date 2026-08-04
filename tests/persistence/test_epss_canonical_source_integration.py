from __future__ import annotations

import os
from datetime import (
    UTC,
    date,
    datetime,
)
from pathlib import Path
from uuid import uuid4

from dotenv import load_dotenv

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)

load_dotenv(
    dotenv_path=PROJECT_ROOT / ".env",
    override=False,
)

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

from infrastructure.persistence.models.normalized import (
    EPSSScoreModel,
)
from infrastructure.persistence.sqlalchemy import (
    create_ingestion_engine,
    create_session_factory,
)
from infrastructure.persistence.sqlalchemy.readers.epss_canonical_source import (
    SqlAlchemyEPSSCanonicalSource,
)


pytestmark = pytest.mark.integration


def test_read_batches_with_real_postgresql(
) -> None:
    database_url = os.environ.get(
        "MIGRATION_DATABASE_URL"
    )

    if not database_url:
        raise RuntimeError(
            "MIGRATION_DATABASE_URL "
            "is not defined"
        )

    base_serial = (
        8_000_000_000_000_000_000
        + uuid4().int
        % 100_000_000_000_000_000
    )

    cve_ids = [
        (
            "CVE-9999-"
            f"{base_serial + index}"
        )
        for index in range(3)
    ]

    cursor = (
        "CVE-9999-"
        f"{base_serial - 1}"
    )

    synchronized_at = [
        datetime(
            2026,
            8,
            2 + index,
            12,
            0,
            tzinfo=UTC,
        )
        for index in range(3)
    ]

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
        with owner_session_factory() as session:
            session.execute(
                text(
                    "SET ROLE threat_intel_owner"
                )
            )

            session.add_all(
                [
                    EPSSScoreModel(
                        cve_id=cve_id,
                        epss_score=(
                            0.10
                            + index * 0.10
                        ),
                        percentile=(
                            0.70
                            + index * 0.05
                        ),
                        score_date=date(
                            2026,
                            8,
                            2 + index,
                        ),
                        api_version="v1",
                        synchronized_at=(
                            synchronized_at[
                                index
                            ]
                        ),
                    )
                    for index, cve_id
                    in enumerate(cve_ids)
                ]
            )

            session.commit()

        with ingestion_session_factory() as session:
            reader = (
                SqlAlchemyEPSSCanonicalSource(
                    session=session,
                )
            )

            first_batch = (
                reader.read_batch(
                    after_cve_id=cursor,
                    limit=2,
                )
            )

            assert [
                record.cve_id
                for record in first_batch
            ] == cve_ids[:2]

            assert (
                first_batch[0]
                .snapshot.score
                == 0.10
            )

            assert (
                first_batch[1]
                .snapshot.score_date
                == date(
                    2026,
                    8,
                    3,
                )
            )

            second_batch = (
                reader.read_batch(
                    after_cve_id=(
                        first_batch[-1]
                        .cve_id
                    ),
                    limit=1,
                )
            )

            assert [
                record.cve_id
                for record in second_batch
            ] == cve_ids[2:]

            assert (
                second_batch[0]
                .synchronized_at
                == synchronized_at[2]
            )

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
                    EPSSScoreModel
                    .cve_id
                    .in_(cve_ids)
                )
            )

            session.commit()

        ingestion_engine.dispose()
        owner_engine.dispose()