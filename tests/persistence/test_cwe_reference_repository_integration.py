from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy.engine import Engine

load_dotenv(
    dotenv_path=Path.cwd() / ".env",
    override=False,
)

import os
from datetime import date
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

from infrastructure.persistence.models.normalized import (
    CisaKevVulnerabilityModel,
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
    create_ingestion_engine,
    create_session_factory,
)
from infrastructure.persistence.sqlalchemy.repositories.cwe_reference_repository import (
    SqlAlchemyVulnerabilityCWEReferenceRepository,
)


pytestmark = pytest.mark.integration


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


def _synthetic_cwe_id(
) -> str:
    numeric_id = (
        800_000_000
        + uuid4().int % 100_000_000
    )

    return f"CWE-{numeric_id}"


def _synthetic_ghsa_id(
) -> str:
    value = uuid4().hex

    return (
        f"GHSA-{value[:4]}-"
        f"{value[4:8]}-"
        f"{value[8:12]}"
    )


def test_list_distinct_ids_with_real_postgresql(
) -> None:
    source_id = uuid4()
    ingestion_run_id = uuid4()

    cisa_raw_payload_id = uuid4()
    github_raw_payload_id = uuid4()

    cisa_vulnerability_id = uuid4()
    github_vulnerability_id = uuid4()

    shared_cwe_id = _synthetic_cwe_id()
    github_only_cwe_id = _synthetic_cwe_id()

    while github_only_cwe_id == shared_cwe_id:
        github_only_cwe_id = (
            _synthetic_cwe_id()
        )

    source_code = (
        "TEST_CWE_REFS_"
        f"{uuid4().hex[:16]}"
    )

    cve_id = (
        "CVE-2099-"
        f"{uuid4().int % 1_000_000_000:09d}"
    )

    ghsa_id = _synthetic_ghsa_id()

    owner_session_factory, owner_engine = (
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

    try:
        with owner_session_factory() as session:
            session.execute(
                text(
                    "SET ROLE threat_intel_owner"
                )
            )

            # 1. La source doit exister avant l'ingestion run.
            session.add(
                SourceModel(
                    id=source_id,
                    code=source_code,
                    name=(
                        "CWE reference repository "
                        "integration test"
                    ),
                )
            )

            session.flush()

            # 2. L'ingestion run dépend de la source.
            session.add(
                IngestionRunModel(
                    id=ingestion_run_id,
                    source_id=source_id,
                    status="completed",
                )
            )

            session.flush()

            # 3. Les payloads dépendent de la source et du run.
            session.add_all(
                [
                    SourcePayloadModel(
                        id=cisa_raw_payload_id,
                        source_id=source_id,
                        ingestion_run_id=(
                            ingestion_run_id
                        ),
                        external_record_id=cve_id,
                        request_url=(
                            "https://example.test/"
                            f"cisa/{cve_id}"
                        ),
                        http_status=200,
                        payload={
                            "cve_id": cve_id,
                        },
                        payload_hash="a" * 64,
                        processing_status=(
                            "processed"
                        ),
                    ),
                    SourcePayloadModel(
                        id=github_raw_payload_id,
                        source_id=source_id,
                        ingestion_run_id=(
                            ingestion_run_id
                        ),
                        external_record_id=ghsa_id,
                        request_url=(
                            "https://example.test/"
                            f"github/{ghsa_id}"
                        ),
                        http_status=200,
                        payload={
                            "ghsa_id": ghsa_id,
                        },
                        payload_hash="b" * 64,
                        processing_status=(
                            "processed"
                        ),
                    ),
                ]
            )

            session.flush()

            # 4. Les données normalisées peuvent maintenant
            # référencer les payloads existants.
            session.add_all(
                [
                    CisaKevVulnerabilityModel(
                        id=cisa_vulnerability_id,
                        raw_payload_id=(
                            cisa_raw_payload_id
                        ),
                        cve_id=cve_id,
                        vendor_project=(
                            "Integration vendor"
                        ),
                        product=(
                            "Integration product"
                        ),
                        vulnerability_name=(
                            "Integration vulnerability"
                        ),
                        date_added=date(
                            2099,
                            1,
                            1,
                        ),
                        short_description=(
                            "CWE reference integration "
                            "test."
                        ),
                        required_action=(
                            "Apply the integration fix."
                        ),
                        due_date=date(
                            2099,
                            2,
                            1,
                        ),
                        known_ransomware_campaign_use=(
                            "unknown"
                        ),
                        cwes=[
                            shared_cwe_id,
                        ],
                        normalizer_version="test",
                    ),
                    GitHubAdvisoryVulnerabilityModel(
                        id=github_vulnerability_id,
                        raw_payload_id=(
                            github_raw_payload_id
                        ),
                        ghsa_id=ghsa_id,
                        cve_id=cve_id,
                        cwe_ids=[
                            shared_cwe_id,
                            github_only_cwe_id,
                        ],
                        normalizer_version="test",
                    ),
                ]
            )

            session.commit()

        with ingestion_session_factory() as session:
            repository = (
                SqlAlchemyVulnerabilityCWEReferenceRepository(
                    session=session,
                )
            )

            result = repository.list_distinct_ids(
                limit=5_000
            )

        assert shared_cwe_id in result
        assert github_only_cwe_id in result

        # Le même identifiant est présent dans CISA et GHAD,
        # mais doit être retourné une seule fois.
        assert result.count(
            shared_cwe_id
        ) == 1

        assert result.count(
            github_only_cwe_id
        ) == 1

    finally:
        with owner_session_factory() as session:
            session.execute(
                text(
                    "SET ROLE threat_intel_owner"
                )
            )

            session.execute(
                delete(
                    GitHubAdvisoryVulnerabilityModel
                ).where(
                    GitHubAdvisoryVulnerabilityModel.id
                    == github_vulnerability_id
                )
            )

            session.execute(
                delete(
                    CisaKevVulnerabilityModel
                ).where(
                    CisaKevVulnerabilityModel.id
                    == cisa_vulnerability_id
                )
            )

            session.execute(
                delete(
                    SourcePayloadModel
                ).where(
                    SourcePayloadModel.id.in_(
                        [
                            cisa_raw_payload_id,
                            github_raw_payload_id,
                        ]
                    )
                )
            )

            session.execute(
                delete(
                    IngestionRunModel
                ).where(
                    IngestionRunModel.id
                    == ingestion_run_id
                )
            )

            session.execute(
                delete(
                    SourceModel
                ).where(
                    SourceModel.id
                    == source_id
                )
            )

            session.commit()

        ingestion_engine.dispose()
        owner_engine.dispose()