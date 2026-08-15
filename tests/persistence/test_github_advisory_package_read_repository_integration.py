from __future__ import annotations

from dotenv import load_dotenv

load_dotenv()

import os
from datetime import UTC, datetime
from uuid import UUID, uuid4

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

from application.ports.outbound.github_advisory_package_read_repository import (
    GitHubAdvisoryPackageKey,
)
from application.ports.outbound.github_advisory_vulnerability_repository import (
    GitHubAdvisoryAffectedPackageData,
    GitHubAdvisoryVulnerabilityData,
)
from application.ports.outbound.raw_payload_repository import (
    RawPayloadData,
)
from infrastructure.persistence.models.normalized import (
    GitHubAdvisoryVulnerabilityModel,
)
from infrastructure.persistence.models.ops import (
    IngestionRunModel,
    SourceModel,
)
from infrastructure.persistence.models.raw import (
    SourcePayloadModel,
)
from infrastructure.persistence.sqlalchemy import (
    SqlAlchemyUnitOfWork,
    create_ingestion_engine,
    create_session_factory,
)
from infrastructure.persistence.sqlalchemy.repositories.github_advisory_package_read_repository import (
    SqlAlchemyGitHubAdvisoryPackageReadRepository,
)


pytestmark = pytest.mark.integration


def _create_owner_session_factory(
) -> sessionmaker[Session]:
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

    return sessionmaker(
        bind=engine,
        class_=Session,
        autoflush=False,
        expire_on_commit=False,
    )


def _ghsa_id() -> str:
    return (
        "GHSA-"
        f"{uuid4().hex[:4]}-"
        f"{uuid4().hex[:4]}-"
        f"{uuid4().hex[:4]}"
    )


def _save_advisory(
    *,
    unit_of_work: SqlAlchemyUnitOfWork,
    source_id: UUID,
    ingestion_run_id: UUID,
    ghsa_id: str,
    package_name: str,
    withdrawn_at: datetime | None = None,
) -> tuple[
    UUID,
    UUID,
]:
    raw_payload_id = (
        unit_of_work.raw_payloads.save(
            RawPayloadData(
                source_id=source_id,
                ingestion_run_id=(
                    ingestion_run_id
                ),
                external_record_id=ghsa_id,
                payload={
                    "ghsa_id": ghsa_id,
                    "package_name": package_name,
                },
                payload_hash=(
                    uuid4().hex
                    + uuid4().hex
                ),
                http_status=200,
                request_url=(
                    "https://api.github.com/"
                    f"advisories/{ghsa_id}"
                ),
            )
        )
    )

    vulnerability_id = (
        unit_of_work
        .github_advisory_vulnerabilities
        .save(
            GitHubAdvisoryVulnerabilityData(
                raw_payload_id=(
                    raw_payload_id
                ),
                ghsa_id=ghsa_id,
                cve_id=None,
                advisory_type="reviewed",
                severity="HIGH",
                withdrawn_at=withdrawn_at,
                affected_packages=(
                    GitHubAdvisoryAffectedPackageData(
                        ecosystem="pip",
                        package_name=package_name,
                        vulnerable_version_range=(
                            ">= 1.0, < 2.0"
                        ),
                        first_patched_version=(
                            "2.0"
                        ),
                    ),
                ),
                normalizer_version="1.0.0",
            )
        )
    )

    return (
        raw_payload_id,
        vulnerability_id,
    )


def test_find_candidates_with_real_postgresql_jsonb() -> None:
    source_id = uuid4()
    ingestion_run_id = uuid4()

    source_code = (
        "TEST_GHAD_PACKAGE_"
        f"{uuid4().hex[:16]}"
    )

    active_ghsa_id = _ghsa_id()
    withdrawn_ghsa_id = _ghsa_id()

    owner_session_factory = (
        _create_owner_session_factory()
    )

    ingestion_engine = (
        create_ingestion_engine()
    )

    ingestion_session_factory = (
        create_session_factory(
            ingestion_engine
        )
    )

    raw_payload_ids: list[UUID] = []
    vulnerability_ids: list[UUID] = []

    with owner_session_factory() as owner_session:
        owner_session.execute(
            text(
                "SET ROLE threat_intel_owner"
            )
        )

        owner_session.add(
            SourceModel(
                id=source_id,
                code=source_code,
                name=(
                    "GitHub Advisory package "
                    "reader integration test"
                ),
            )
        )

        owner_session.commit()

    try:
        with ingestion_session_factory() as session:
            session.add(
                IngestionRunModel(
                    id=ingestion_run_id,
                    source_id=source_id,
                    status="running",
                )
            )

            session.commit()

        unit_of_work = SqlAlchemyUnitOfWork(
            session_factory=(
                ingestion_session_factory
            ),
        )

        with unit_of_work:
            (
                active_raw_payload_id,
                active_vulnerability_id,
            ) = _save_advisory(
                unit_of_work=unit_of_work,
                source_id=source_id,
                ingestion_run_id=(
                    ingestion_run_id
                ),
                ghsa_id=active_ghsa_id,
                package_name=(
                    "Requests_Security.Test"
                ),
            )

            (
                withdrawn_raw_payload_id,
                withdrawn_vulnerability_id,
            ) = _save_advisory(
                unit_of_work=unit_of_work,
                source_id=source_id,
                ingestion_run_id=(
                    ingestion_run_id
                ),
                ghsa_id=withdrawn_ghsa_id,
                package_name=(
                    "Requests_Security.Test"
                ),
                withdrawn_at=datetime(
                    2026,
                    8,
                    15,
                    12,
                    0,
                    tzinfo=UTC,
                ),
            )

            raw_payload_ids.extend(
                [
                    active_raw_payload_id,
                    withdrawn_raw_payload_id,
                ]
            )

            vulnerability_ids.extend(
                [
                    active_vulnerability_id,
                    withdrawn_vulnerability_id,
                ]
            )

            unit_of_work.commit()

        with ingestion_session_factory() as session:
            repository = (
                SqlAlchemyGitHubAdvisoryPackageReadRepository(
                    session=session,
                )
            )

            candidates = (
                repository.find_candidates(
                    package_keys=[
                        GitHubAdvisoryPackageKey(
                            ecosystem="pypi",
                            package_name=(
                                "requests-security-test"
                            ),
                        )
                    ],
                )
            )

        assert len(candidates) == 1

        candidate = candidates[0]

        assert (
            candidate.ghsa_id
            == active_ghsa_id
        )

        assert (
            candidate.ecosystem
            == "pip"
        )

        assert (
            candidate.package_name
            == "Requests_Security.Test"
        )

        assert (
            candidate.vulnerable_version_range
            == ">= 1.0, < 2.0"
        )

        assert (
            candidate.first_patched_version
            == "2.0"
        )

        assert candidate.severity == "HIGH"

        assert (
            candidate.ghsa_id
            != withdrawn_ghsa_id
        )

    finally:
        with owner_session_factory() as owner_session:
            owner_session.execute(
                text(
                    "SET ROLE threat_intel_owner"
                )
            )

            if vulnerability_ids:
                owner_session.execute(
                    delete(
                        GitHubAdvisoryVulnerabilityModel
                    ).where(
                        GitHubAdvisoryVulnerabilityModel
                        .id
                        .in_(
                            vulnerability_ids
                        )
                    )
                )

            if raw_payload_ids:
                owner_session.execute(
                    delete(
                        SourcePayloadModel
                    ).where(
                        SourcePayloadModel
                        .id
                        .in_(
                            raw_payload_ids
                        )
                    )
                )

            owner_session.execute(
                delete(
                    IngestionRunModel
                ).where(
                    IngestionRunModel.id
                    == ingestion_run_id
                )
            )

            owner_session.execute(
                delete(
                    SourceModel
                ).where(
                    SourceModel.id
                    == source_id
                )
            )

            owner_session.commit()