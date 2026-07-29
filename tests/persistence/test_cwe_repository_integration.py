from __future__ import annotations

from dotenv import load_dotenv

load_dotenv()

import os
from dataclasses import replace
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

from domain.cwe_weakness import CWEWeakness
from infrastructure.persistence.models.normalized import (
    CWEWeaknessModel,
)
from infrastructure.persistence.sqlalchemy import (
    SqlAlchemyUnitOfWork,
    create_ingestion_engine,
    create_session_factory,
)


pytestmark = pytest.mark.integration


def _build_weakness(
    *,
    cwe_id: str,
    name: str = "Integration CWE weakness",
) -> CWEWeakness:
    return CWEWeakness(
        id=cwe_id,
        name=name,
        description=(
            "CWE repository integration test."
        ),
        abstraction="Base",
        structure="Simple",
        status="Stable",
        extended_description=(
            "Persistent integration description."
        ),
        likelihood_of_exploit="High",
        mapping_usage="Allowed",
        mapping_rationale="Direct mapping",
        relationships=(
            {
                "nature": "ChildOf",
                "cwe_id": "CWE-74",
            },
        ),
        consequences=(
            {
                "scope": "Confidentiality",
                "impact": "Read Application Data",
            },
        ),
        mitigations=(
            {
                "phase": "Implementation",
                "description": "Validate input.",
            },
        ),
        detection_methods=(
            {
                "method": "Static Analysis",
            },
        ),
        applicable_platforms=(
            {
                "type": "Language",
                "name": "Python",
            },
        ),
        modes_of_introduction=(
            {
                "phase": "Implementation",
            },
        ),
        alternate_terms=(
            "Integration alias",
        ),
        related_capec_ids=(
            "CAPEC-63",
        ),
        catalog_version="4.20",
        catalog_date="2026-04-30",
    )


def test_upsert_and_read_with_real_postgresql(
) -> None:
    database_url = os.environ.get(
        "MIGRATION_DATABASE_URL"
    )

    if not database_url:
        raise RuntimeError(
            "MIGRATION_DATABASE_URL is not defined"
        )

    numeric_id = (
        900_000_000
        + uuid4().int % 99_000_000
    )

    cwe_id = f"CWE-{numeric_id}"

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

        initial = _build_weakness(
            cwe_id=cwe_id
        )

        with unit_of_work:
            count = (
                unit_of_work
                .cwe_weaknesses
                .upsert_many(
                    [
                        initial,
                    ]
                )
            )

            assert count == 1

            unit_of_work.commit()

        with unit_of_work:
            persisted = (
                unit_of_work
                .cwe_weaknesses
                .find_by_id(
                    cwe_id
                )
            )

            assert persisted is not None
            assert persisted.id == cwe_id
            assert persisted.name == (
                "Integration CWE weakness"
            )
            assert persisted.relationships == (
                {
                    "nature": "ChildOf",
                    "cwe_id": "CWE-74",
                },
            )

        updated = replace(
            initial,
            name=(
                "Updated integration "
                "CWE weakness"
            ),
            catalog_version="4.21",
        )

        with unit_of_work:
            count = (
                unit_of_work
                .cwe_weaknesses
                .upsert_many(
                    [
                        updated,
                    ]
                )
            )

            assert count == 1

            unit_of_work.commit()

        with ingestion_session_factory() as session:
            model = session.get(
                CWEWeaknessModel,
                cwe_id,
            )

            assert model is not None
            assert model.name == (
                "Updated integration "
                "CWE weakness"
            )
            assert model.catalog_version == "4.21"
            assert model.alternate_terms == [
                "Integration alias",
            ]
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
                    CWEWeaknessModel
                ).where(
                    CWEWeaknessModel.cwe_id
                    == cwe_id
                )
            )

            session.commit()

        ingestion_engine.dispose()
        owner_engine.dispose()