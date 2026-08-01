from __future__ import annotations

import os
from collections import Counter
from uuid import UUID, uuid4

from dotenv import load_dotenv

load_dotenv()

import pytest
from sqlalchemy import (
    Engine,
    create_engine,
    delete,
    select,
    text,
)
from sqlalchemy.orm import Session, sessionmaker

from application.ports.outbound.ingestion_run_payload_repository import (
    IngestionRunPayloadLink,
)
from application.ports.outbound.raw_payload_repository import (
    RawPayloadData,
)
from application.services.cisa_kev_normalization_service import (
    CisaKevNormalizationService,
)
from application.services.cisa_kev_normalizer import (
    CisaKevNormalizer,
)
from infrastructure.adapters.inbound.cisa_kev_normalization_job import (
    CisaKevNormalizationJob,
    CisaKevNormalizationJobResult,
)
from infrastructure.persistence.models.normalized import (
    CisaKevVulnerabilityModel,
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


def _create_owner_resources() -> tuple[
    Engine,
    sessionmaker[Session],
]:
    """
    Crée une connexion disposant des droits nécessaires pour
    préparer et nettoyer les données d'intégration.

    Cette connexion ne doit jamais pointer vers la production.
    """

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

    session_factory = sessionmaker(
        bind=engine,
        class_=Session,
        autoflush=False,
        expire_on_commit=False,
    )

    return engine, session_factory


def _create_source_and_run(
    *,
    owner_session_factory: sessionmaker[Session],
    ingestion_session_factory: sessionmaker[Session],
    source_id: UUID,
    ingestion_run_id: UUID,
    source_code: str,
) -> None:
    """
    Prépare une source isolée et une exécution d'ingestion.
    """

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
                    "CISA normalization job "
                    "integration test"
                ),
            )
        )

        session.commit()

    with ingestion_session_factory() as session:
        session.add(
            IngestionRunModel(
                id=ingestion_run_id,
                source_id=source_id,
                status="completed",
            )
        )

        session.commit()


def _save_pending_payload(
    *,
    ingestion_session_factory: sessionmaker[Session],
    source_id: UUID,
    ingestion_run_id: UUID,
    external_record_id: str,
    payload: dict[str, object],
) -> UUID:
    """
    Persiste un payload brut pending avec un hash unique.
    """

    unit_of_work = SqlAlchemyUnitOfWork(
        session_factory=ingestion_session_factory,
    )

    with unit_of_work:
        payload_id = (
            unit_of_work.raw_payloads.save(
                RawPayloadData(
                    source_id=source_id,
                    ingestion_run_id=(
                        ingestion_run_id
                    ),
                    external_record_id=(
                        external_record_id
                    ),
                    payload=payload,
                    payload_hash=uuid4().hex * 2,
                    http_status=200,
                    processing_status="pending",
                )
            )
        )

        link_result = (
            unit_of_work
            .ingestion_run_payloads
            .link_many_ignore_existing(
                (
                    IngestionRunPayloadLink(
                        ingestion_run_id=(
                            ingestion_run_id
                        ),
                        raw_payload_id=payload_id,
                    ),
                )
            )
        )

        if (
            link_result.unique_count != 1
            or link_result.inserted_count != 1
        ):
            raise RuntimeError(
                "Unable to link the raw payload "
                "to its ingestion run"
            )

        unit_of_work.commit()

    return payload_id


def _build_valid_payload(
    *,
    cve_id: str,
    product: str,
) -> dict[str, object]:
    return {
        "cveID": cve_id,
        "vendorProject": "Integration Vendor",
        "product": product,
        "vulnerabilityName": (
            f"{product} integration vulnerability"
        ),
        "dateAdded": "2026-07-20",
        "shortDescription": (
            "A vulnerability used by the CISA "
            "runner integration test."
        ),
        "requiredAction": (
            "Apply the vendor mitigation."
        ),
        "dueDate": "2026-08-10",
        "knownRansomwareCampaignUse": "Unknown",
        "notes": "Runner integration test.",
        "cwes": [
            "CWE-79",
            "CWE-89",
        ],
    }


def _build_invalid_payload(
    *,
    cve_id: str,
) -> dict[str, object]:
    """
    Produit un payload invalide contenant une valeur sensible.

    Le secret doit être supprimé du message d'erreur persistant.
    """

    return {
        "cveID": cve_id,
        "vendorProject": "Integration Vendor",
        "product": "Invalid Product",
        "vulnerabilityName": (
            "Invalid integration vulnerability"
        ),
        "dateAdded": "2026-07-20",
        "shortDescription": (
            "An intentionally invalid payload."
        ),
        "requiredAction": (
            "Apply the vendor mitigation."
        ),
        "dueDate": "2026-08-10",
        "knownRansomwareCampaignUse": "Unknown",
        "cwes": [
            "api_key=super-secret-value",
        ],
    }


def _delete_test_data(
    *,
    owner_session_factory: sessionmaker[Session],
    source_id: UUID,
) -> None:
    """
    Supprime les données dans l'ordre des clés étrangères.
    """

    with owner_session_factory() as session:
        session.execute(
            text(
                "SET ROLE threat_intel_owner"
            )
        )

        ingestion_run_ids = (
            select(
                IngestionRunModel.id
            )
            .where(
                IngestionRunModel.source_id
                == source_id
            )
        )

        payload_ids = (
            select(
                SourcePayloadModel.id
            )
            .where(
                SourcePayloadModel
                .ingestion_run_id
                .in_(
                    ingestion_run_ids
                )
            )
        )

        session.execute(
            delete(
                CisaKevVulnerabilityModel
            ).where(
                CisaKevVulnerabilityModel
                .raw_payload_id
                .in_(payload_ids)
            )
        )

        session.execute(
            delete(
                SourcePayloadModel
            ).where(
                SourcePayloadModel
                .ingestion_run_id
                .in_(
                    ingestion_run_ids
                )
            )
        )

        session.execute(
            delete(
                IngestionRunModel
            ).where(
                IngestionRunModel.source_id
                == source_id
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


def test_job_processes_multiple_batches_and_is_idempotent(
) -> None:
    """
    Vérifie le runner complet avec PostgreSQL :

    - plusieurs lots limités ;
    - payloads valides normalisés ;
    - payload invalide marqué failed ;
    - message d'erreur assaini ;
    - correspondance processed/normalized ;
    - deuxième exécution idempotente.
    """

    source_id = uuid4()
    ingestion_run_id = uuid4()

    source_code = (
        "TEST_CISA_RUNNER_"
        f"{uuid4().hex[:16]}"
    )

    owner_engine, owner_session_factory = (
        _create_owner_resources()
    )

    ingestion_engine = create_ingestion_engine()

    ingestion_session_factory = (
        create_session_factory(
            ingestion_engine
        )
    )

    _create_source_and_run(
        owner_session_factory=(
            owner_session_factory
        ),
        ingestion_session_factory=(
            ingestion_session_factory
        ),
        source_id=source_id,
        ingestion_run_id=ingestion_run_id,
        source_code=source_code,
    )

    try:
        first_cve_id = (
            "CVE-2099-"
            f"{uuid4().int % 1_000_000_000:09d}"
        )

        second_cve_id = (
            "CVE-2099-"
            f"{uuid4().int % 1_000_000_000:09d}"
        )

        invalid_cve_id = (
            "CVE-2099-"
            f"{uuid4().int % 1_000_000_000:09d}"
        )

        _save_pending_payload(
            ingestion_session_factory=(
                ingestion_session_factory
            ),
            source_id=source_id,
            ingestion_run_id=ingestion_run_id,
            external_record_id=first_cve_id,
            payload=_build_valid_payload(
                cve_id=first_cve_id,
                product="Product One",
            ),
        )

        _save_pending_payload(
            ingestion_session_factory=(
                ingestion_session_factory
            ),
            source_id=source_id,
            ingestion_run_id=ingestion_run_id,
            external_record_id=second_cve_id,
            payload=_build_valid_payload(
                cve_id=second_cve_id,
                product="Product Two",
            ),
        )

        _save_pending_payload(
            ingestion_session_factory=(
                ingestion_session_factory
            ),
            source_id=source_id,
            ingestion_run_id=ingestion_run_id,
            external_record_id=invalid_cve_id,
            payload=_build_invalid_payload(
                cve_id=invalid_cve_id,
            ),
        )

        unit_of_work = SqlAlchemyUnitOfWork(
            session_factory=(
                ingestion_session_factory
            ),
        )

        service = CisaKevNormalizationService(
            unit_of_work=unit_of_work,
            normalizer=CisaKevNormalizer(),
        )

        job = CisaKevNormalizationJob(
            normalization_service=service,
            source_id=source_id,
            source_code=source_code,
            batch_size=2,
            max_batches=10,
        )

        result = job.run()

        assert result == (
            CisaKevNormalizationJobResult(
                batches=2,
                claimed=3,
                normalized=2,
                already_normalized=0,
                failed=1,
                requeued=0,
                stale_failed=0,
            )
        )

        with ingestion_session_factory() as session:
            raw_payloads = list(
                session.execute(
                    select(
                        SourcePayloadModel
                    ).where(
                        SourcePayloadModel
                        .ingestion_run_id
                        == ingestion_run_id
                    )
                )
                .scalars()
                .all()
            )

            raw_payload_ids = {
                payload.id
                for payload in raw_payloads
            }

            normalized_rows = list(
                session.execute(
                    select(
                        CisaKevVulnerabilityModel
                    ).where(
                        CisaKevVulnerabilityModel
                        .raw_payload_id
                        .in_(
                            raw_payload_ids
                        )
                    )
                )
                .scalars()
                .all()
            )

            status_counts = Counter(
                payload.processing_status
                for payload in raw_payloads
            )

            assert len(
                raw_payloads
            ) == 3

            assert status_counts == {
                "processed": 2,
                "failed": 1,
            }

            assert len(
                normalized_rows
            ) == 2

            processed_payload_ids = {
                payload.id
                for payload in raw_payloads
                if (
                    payload.processing_status
                    == "processed"
                )
            }

            normalized_payload_ids = {
                vulnerability.raw_payload_id
                for vulnerability
                in normalized_rows
            }

            assert (
                normalized_payload_ids
                == processed_payload_ids
            )

            assert all(
                payload.processing_attempts
                == 1
                for payload in raw_payloads
            )

            failed_payload = next(
                payload
                for payload in raw_payloads
                if (
                    payload.processing_status
                    == "failed"
                )
            )

            assert failed_payload.error_message

            assert (
                "super-secret-value"
                not in failed_payload.error_message
            )

            assert (
                "[REDACTED]"
                in failed_payload.error_message
            )

        second_result = job.run()

        assert second_result == (
            CisaKevNormalizationJobResult(
                batches=0,
                claimed=0,
                normalized=0,
                already_normalized=0,
                failed=0,
                requeued=0,
                stale_failed=0,
            )
        )

        with ingestion_session_factory() as session:
            normalized_count = len(
                session.execute(
                    select(
                        CisaKevVulnerabilityModel.id
                    ).where(
                        CisaKevVulnerabilityModel
                        .raw_payload_id
                        .in_(
                            raw_payload_ids
                        )
                    )
                )
                .scalars()
                .all()
            )

            assert normalized_count == 2

    finally:
        _delete_test_data(
            owner_session_factory=(
                owner_session_factory
            ),
            source_id=source_id,
        )

        ingestion_engine.dispose()
        owner_engine.dispose()