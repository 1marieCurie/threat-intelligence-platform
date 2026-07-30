from __future__ import annotations

from dotenv import load_dotenv

load_dotenv()

from collections.abc import Iterator
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from infrastructure.persistence.sqlalchemy import (
    create_ingestion_engine,
    create_session_factory,
)


pytestmark = pytest.mark.integration


@pytest.fixture
def ingestion_session_factory(
) -> Iterator[sessionmaker[Session]]:
    engine = create_ingestion_engine()

    session_factory = create_session_factory(
        engine
    )

    try:
        yield session_factory
    finally:
        engine.dispose()


def _unique_cve_id() -> str:
    serial_number = (
        100_000_000
        + uuid4().int % 900_000_000
    )

    return f"CVE-2026-{serial_number}"


def test_epss_table_has_expected_columns(
    ingestion_session_factory: (
        sessionmaker[Session]
    ),
) -> None:
    with ingestion_session_factory() as session:
        rows = (
            session.execute(
                text(
                    """
                    SELECT
                        column_name,
                        data_type,
                        is_nullable
                    FROM information_schema.columns
                    WHERE table_schema = 'normalized'
                      AND table_name = 'epss_score'
                    ORDER BY ordinal_position
                    """
                )
            )
            .mappings()
            .all()
        )

    columns = {
        row["column_name"]: {
            "data_type": row["data_type"],
            "is_nullable": row["is_nullable"],
        }
        for row in rows
    }

    assert columns == {
        "cve_id": {
            "data_type": "character varying",
            "is_nullable": "NO",
        },
        "epss_score": {
            "data_type": "double precision",
            "is_nullable": "NO",
        },
        "percentile": {
            "data_type": "double precision",
            "is_nullable": "NO",
        },
        "score_date": {
            "data_type": "date",
            "is_nullable": "NO",
        },
        "api_version": {
            "data_type": "character varying",
            "is_nullable": "YES",
        },
        "synchronized_at": {
            "data_type": (
                "timestamp with time zone"
            ),
            "is_nullable": "NO",
        },
    }


def test_database_rejects_invalid_cve_identifier(
    ingestion_session_factory: (
        sessionmaker[Session]
    ),
) -> None:
    with ingestion_session_factory() as session:
        with pytest.raises(
            IntegrityError,
        ):
            session.execute(
                text(
                    """
                    INSERT INTO normalized.epss_score (
                        cve_id,
                        epss_score,
                        percentile,
                        score_date
                    )
                    VALUES (
                        :cve_id,
                        :epss_score,
                        :percentile,
                        :score_date
                    )
                    """
                ),
                {
                    "cve_id": "INVALID-2026-1234",
                    "epss_score": 0.50,
                    "percentile": 0.80,
                    "score_date": "2026-07-30",
                },
            )

            session.commit()

        session.rollback()


@pytest.mark.parametrize(
    (
        "epss_score",
        "percentile",
    ),
    [
        (
            -0.01,
            0.50,
        ),
        (
            1.01,
            0.50,
        ),
        (
            0.50,
            -0.01,
        ),
        (
            0.50,
            1.01,
        ),
    ],
)
def test_database_rejects_out_of_range_values(
    ingestion_session_factory: (
        sessionmaker[Session]
    ),
    epss_score: float,
    percentile: float,
) -> None:
    with ingestion_session_factory() as session:
        with pytest.raises(
            IntegrityError,
        ):
            session.execute(
                text(
                    """
                    INSERT INTO normalized.epss_score (
                        cve_id,
                        epss_score,
                        percentile,
                        score_date
                    )
                    VALUES (
                        :cve_id,
                        :epss_score,
                        :percentile,
                        :score_date
                    )
                    """
                ),
                {
                    "cve_id": _unique_cve_id(),
                    "epss_score": epss_score,
                    "percentile": percentile,
                    "score_date": "2026-07-30",
                },
            )

            session.commit()

        session.rollback()


def test_ingestion_role_has_minimum_required_permissions(
    ingestion_session_factory: (
        sessionmaker[Session]
    ),
) -> None:
    with ingestion_session_factory() as session:
        permissions = (
            session.execute(
                text(
                    """
                    SELECT
                        has_table_privilege(
                            current_user,
                            'normalized.epss_score',
                            'SELECT'
                        ) AS can_select,
                        has_table_privilege(
                            current_user,
                            'normalized.epss_score',
                            'INSERT'
                        ) AS can_insert,
                        has_table_privilege(
                            current_user,
                            'normalized.epss_score',
                            'UPDATE'
                        ) AS can_update,
                        has_table_privilege(
                            current_user,
                            'normalized.epss_score',
                            'DELETE'
                        ) AS can_delete,
                        has_table_privilege(
                            current_user,
                            'normalized.epss_score',
                            'TRUNCATE'
                        ) AS can_truncate
                    """
                )
            )
            .mappings()
            .one()
        )

    assert permissions["can_select"] is True
    assert permissions["can_insert"] is True
    assert permissions["can_update"] is True

    assert permissions["can_delete"] is False
    assert permissions["can_truncate"] is False