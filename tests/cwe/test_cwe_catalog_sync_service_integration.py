from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv

load_dotenv(
    dotenv_path=Path.cwd() / ".env",
    override=False,
)

import os
from collections.abc import Iterable
from datetime import date
from typing import Any
from uuid import uuid4

import pytest
from sqlalchemy import (
    create_engine,
    delete,
    text,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import (
    Session,
    sessionmaker,
)

from application.services.cwe_catalog_sync_service import (
    CWECatalogSyncService,
)
from infrastructure.persistence.models.normalized import (
    CisaKevVulnerabilityModel,
    CWEWeaknessModel,
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


pytestmark = pytest.mark.integration


class SelectiveFakeCWECatalogClient:
    """
    Faux client MITRE utilisé avec PostgreSQL réel.

    Il retourne uniquement les identifiants synthétiques créés
    par ce test. Les autres CWE présents dans la base sont traités
    comme absents, sans être écrasés par des données de test.
    """

    def __init__(
        self,
        *,
        allowed_ids: set[str],
    ) -> None:
        self._allowed_ids = set(
            allowed_ids
        )

        self.version_calls = 0

        self.weakness_calls: list[
            list[str | int]
        ] = []

    def fetch_version(
        self,
    ) -> dict[str, Any]:
        self.version_calls += 1

        return {
            "ContentVersion": "4.20-test",
            "ContentDate": "2026-07-30",
        }

    def fetch_weaknesses(
        self,
        cwe_ids: Iterable[str | int],
    ) -> dict[str, Any]:
        requested_ids = list(
            cwe_ids
        )

        self.weakness_calls.append(
            requested_ids
        )

        weaknesses: list[
            dict[str, Any]
        ] = []

        for raw_id in requested_ids:
            cwe_id = str(
                raw_id
            ).strip().upper()

            if cwe_id not in self._allowed_ids:
                continue

            weaknesses.append(
                {
                    "ID": cwe_id,
                    "Name": (
                        "Integration weakness "
                        f"{cwe_id}"
                    ),
                    "Description": (
                        "Synthetic CWE entry used "
                        "to validate the complete "
                        "PostgreSQL synchronization."
                    ),
                    "Abstraction": "Base",
                    "Structure": "Simple",
                    "Status": "Stable",
                    "LikelihoodOfExploit": "High",
                    "AlternateTerms": [
                        {
                            "Term": (
                                "Integration "
                                f"{cwe_id}"
                            ),
                        },
                    ],
                    "RelatedAttackPatterns": [
                        {
                            "CAPECID": "63",
                        },
                    ],
                }
            )

        return {
            "Weaknesses": weaknesses,
        }


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


def test_synchronize_referenced_with_real_postgresql(
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

    synthetic_cwe_ids = {
        shared_cwe_id,
        github_only_cwe_id,
    }

    source_code = (
        "TEST_CWE_SYNC_"
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
        # ========================================================
        # Préparation des références CISA et GHAD
        # ========================================================

        with owner_session_factory() as session:
            session.execute(
                text(
                    "SET ROLE threat_intel_owner"
                )
            )

            session.add(
                SourceModel(
                    id=source_id,
                    code=source_code,
                    name=(
                        "CWE synchronization "
                        "integration test"
                    ),
                )
            )

            session.flush()

            session.add(
                IngestionRunModel(
                    id=ingestion_run_id,
                    source_id=source_id,
                    status="completed",
                )
            )

            session.flush()

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
                        payload_hash="c" * 64,
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
                        payload_hash="g" * 64,
                        processing_status=(
                            "processed"
                        ),
                    ),
                ]
            )

            session.flush()

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
                            "CWE synchronization "
                            "integration test."
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

        # ========================================================
        # Exécution réelle du service
        # ========================================================

        client = (
            SelectiveFakeCWECatalogClient(
                allowed_ids=synthetic_cwe_ids
            )
        )

        unit_of_work = SqlAlchemyUnitOfWork(
            session_factory=(
                ingestion_session_factory
            )
        )

        service = CWECatalogSyncService(
            client=client,
            unit_of_work=unit_of_work,
            batch_size=10,
            max_cwe_ids=5_000,
        )

        result = (
            service.synchronize_referenced()
        )

        # ========================================================
        # Validation du résultat applicatif
        # ========================================================

        assert result.catalog_version == (
            "4.20-test"
        )

        assert result.catalog_date == (
            "2026-07-30"
        )

        assert result.requested_ids >= 2
        assert result.fetched_weaknesses == 2
        assert result.persisted_weaknesses == 2
        assert result.batches >= 1

        assert shared_cwe_id not in (
            result.missing_ids
        )

        assert github_only_cwe_id not in (
            result.missing_ids
        )

        assert client.version_calls == 1

        assert len(
            client.weakness_calls
        ) == result.batches

        assert sum(
            len(batch)
            for batch in client.weakness_calls
        ) == result.requested_ids

        # ========================================================
        # Validation PostgreSQL
        # ========================================================

        with ingestion_session_factory() as session:
            shared_model = session.get(
                CWEWeaknessModel,
                shared_cwe_id,
            )

            github_only_model = session.get(
                CWEWeaknessModel,
                github_only_cwe_id,
            )

            assert shared_model is not None

            assert shared_model.name == (
                "Integration weakness "
                f"{shared_cwe_id}"
            )

            assert shared_model.catalog_version == (
                "4.20-test"
            )

            assert shared_model.catalog_date == (
                "2026-07-30"
            )

            assert shared_model.related_capec_ids == [
                "CAPEC-63",
            ]

            assert github_only_model is not None

            assert github_only_model.name == (
                "Integration weakness "
                f"{github_only_cwe_id}"
            )

            assert (
                github_only_model
                .synchronized_at
                is not None
            )

    finally:
        # ========================================================
        # Nettoyage des données synthétiques
        # ========================================================

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
                    CWEWeaknessModel.cwe_id.in_(
                        list(
                            synthetic_cwe_ids
                        )
                    )
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