from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from dotenv import load_dotenv

load_dotenv()

import pytest
from sqlalchemy import (
    create_engine,
    delete,
    select,
    text,
    update,
)
from sqlalchemy.orm import Session, sessionmaker

from application.ports.outbound.raw_payload_repository import (
    RawPayloadData,
)
from application.services.cisa_kev_normalization_service import (
    CisaKevNormalizationService,
)
from application.services.cisa_kev_normalizer import (
    CisaKevNormalizer,
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


def _create_owner_session_factory() -> sessionmaker[Session]:
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


def _create_source_and_run(
    *,
    owner_session_factory: sessionmaker[Session],
    ingestion_session_factory: sessionmaker[Session],
    source_id: UUID,
    ingestion_run_id: UUID,
    source_code: str,
) -> None:
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
                    "CISA normalization service "
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


def _delete_test_data(
    *,
    owner_session_factory: sessionmaker[Session],
    source_id: UUID,
) -> None:
    with owner_session_factory() as session:
        session.execute(
            text(
                "SET ROLE threat_intel_owner"
            )
        )

        run_ids = (
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
                .in_(run_ids)
            )
        )

        # Respect de l’ordre des clés étrangères :
        # normalized -> raw -> ingestion_run -> source.
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
                .in_(run_ids)
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


def _save_pending_payload(
    *,
    ingestion_session_factory: sessionmaker[Session],
    source_id: UUID,
    ingestion_run_id: UUID,
    external_record_id: str,
    payload: dict[str, object],
) -> UUID:
    unit_of_work = SqlAlchemyUnitOfWork(
        session_factory=ingestion_session_factory,
    )

    with unit_of_work:
        payload_id = unit_of_work.raw_payloads.save(
            RawPayloadData(
                source_id=source_id,
                ingestion_run_id=ingestion_run_id,
                external_record_id=(
                    external_record_id
                ),
                payload=payload,
                payload_hash=uuid4().hex * 2,
                http_status=200,
                processing_status="pending",
            )
        )

        unit_of_work.commit()

    return payload_id


def _force_processing_lease(
    *,
    ingestion_session_factory: sessionmaker[Session],
    payload_id: UUID,
    processing_started_at: datetime,
    processing_attempts: int,
) -> None:
    with ingestion_session_factory() as session:
        statement = (
            update(
                SourcePayloadModel
            )
            .where(
                SourcePayloadModel.id
                == payload_id
            )
            .values(
                processing_status="processing",
                processing_started_at=(
                    processing_started_at
                ),
                processing_attempts=(
                    processing_attempts
                ),
                error_message=None,
            )
            .returning(
                SourcePayloadModel.id
            )
        )

        updated_payload_id = (
            session.execute(statement)
            .scalar_one_or_none()
        )

        assert updated_payload_id == payload_id

        session.commit()


def test_process_pending_persists_normalized_vulnerability() -> None:
    source_id = uuid4()
    ingestion_run_id = uuid4()

    source_code = (
        f"TEST_CISA_NORMALIZE_{uuid4().hex[:16]}"
    )

    cve_id = (
        f"CVE-2099-"
        f"{uuid4().int % 1_000_000_000:09d}"
    )

    owner_session_factory = (
        _create_owner_session_factory()
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
        payload_id = _save_pending_payload(
            ingestion_session_factory=(
                ingestion_session_factory
            ),
            source_id=source_id,
            ingestion_run_id=ingestion_run_id,
            external_record_id=cve_id,
            payload={
                "cveID": cve_id,
                "vendorProject": "Test Vendor",
                "product": "Test Product",
                "vulnerabilityName": (
                    "Test Product vulnerability"
                ),
                "dateAdded": "2026-07-20",
                "shortDescription": (
                    "A vulnerability affects "
                    "the test product."
                ),
                "requiredAction": (
                    "Apply vendor mitigations."
                ),
                "dueDate": "2026-08-10",
                "knownRansomwareCampaignUse": (
                    "Unknown"
                ),
                "notes": "Integration test.",
                "cwes": [
                    "CWE-79",
                    "CWE-89",
                ],
            },
        )

        service = CisaKevNormalizationService(
            unit_of_work=SqlAlchemyUnitOfWork(
                session_factory=(
                    ingestion_session_factory
                ),
            ),
            normalizer=CisaKevNormalizer(),
        )

        result = service.process_pending(
            source_id=source_id,
            limit=10,
        )

        assert result.claimed == 1
        assert result.normalized == 1
        assert result.already_normalized == 0
        assert result.failed == 0
        assert result.requeued == 0
        assert result.stale_failed == 0

        with ingestion_session_factory() as session:
            raw_payload = session.get(
                SourcePayloadModel,
                payload_id,
            )

            vulnerability = (
                session.execute(
                    select(
                        CisaKevVulnerabilityModel
                    ).where(
                        CisaKevVulnerabilityModel
                        .raw_payload_id
                        == payload_id
                    )
                )
                .scalar_one_or_none()
            )

            assert raw_payload is not None

            assert (
                raw_payload.processing_status
                == "processed"
            )
            assert (
                raw_payload.processing_started_at
                is None
            )
            assert (
                raw_payload.processing_attempts
                == 1
            )
            assert raw_payload.error_message is None

            assert vulnerability is not None
            assert vulnerability.cve_id == cve_id

            assert (
                vulnerability.vendor_project
                == "Test Vendor"
            )

            assert vulnerability.cwes == [
                "CWE-79",
                "CWE-89",
            ]

            assert (
                vulnerability.normalizer_version
                == "1.0.0"
            )

        second_result = service.process_pending(
            source_id=source_id,
            limit=10,
        )

        assert second_result.claimed == 0
        assert second_result.normalized == 0
        assert second_result.requeued == 0
        assert second_result.stale_failed == 0

    finally:
        _delete_test_data(
            owner_session_factory=(
                owner_session_factory
            ),
            source_id=source_id,
        )

        ingestion_engine.dispose()


def test_invalid_payload_is_marked_failed_and_redacted() -> None:
    source_id = uuid4()
    ingestion_run_id = uuid4()

    source_code = (
        f"TEST_CISA_FAILURE_{uuid4().hex[:18]}"
    )

    cve_id = (
        f"CVE-2099-"
        f"{uuid4().int % 1_000_000_000:09d}"
    )

    owner_session_factory = (
        _create_owner_session_factory()
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
        payload_id = _save_pending_payload(
            ingestion_session_factory=(
                ingestion_session_factory
            ),
            source_id=source_id,
            ingestion_run_id=ingestion_run_id,
            external_record_id=cve_id,
            payload={
                "cveID": cve_id,
                "vendorProject": "Test Vendor",
                "product": "Test Product",
                "vulnerabilityName": (
                    "Test vulnerability"
                ),
                "dateAdded": "2026-07-20",
                "shortDescription": (
                    "Invalid test payload."
                ),
                "requiredAction": (
                    "Apply vendor mitigations."
                ),
                "dueDate": "2026-08-10",
                "knownRansomwareCampaignUse": (
                    "Unknown"
                ),
                "cwes": [
                    "api_key=super-secret-value",
                ],
            },
        )

        service = CisaKevNormalizationService(
            unit_of_work=SqlAlchemyUnitOfWork(
                session_factory=(
                    ingestion_session_factory
                ),
            ),
            normalizer=CisaKevNormalizer(),
        )

        result = service.process_pending(
            source_id=source_id,
            limit=10,
        )

        assert result.claimed == 1
        assert result.normalized == 0
        assert result.already_normalized == 0
        assert result.failed == 1
        assert result.requeued == 0
        assert result.stale_failed == 0

        with ingestion_session_factory() as session:
            raw_payload = session.get(
                SourcePayloadModel,
                payload_id,
            )

            vulnerability = (
                session.execute(
                    select(
                        CisaKevVulnerabilityModel
                    ).where(
                        CisaKevVulnerabilityModel
                        .raw_payload_id
                        == payload_id
                    )
                )
                .scalar_one_or_none()
            )

            assert raw_payload is not None

            assert (
                raw_payload.processing_status
                == "failed"
            )
            assert (
                raw_payload.processing_started_at
                is None
            )
            assert (
                raw_payload.processing_attempts
                == 1
            )
            assert raw_payload.error_message is not None

            assert (
                "super-secret-value"
                not in raw_payload.error_message
            )
            assert (
                "[REDACTED]"
                in raw_payload.error_message
            )

            assert vulnerability is None

    finally:
        _delete_test_data(
            owner_session_factory=(
                owner_session_factory
            ),
            source_id=source_id,
        )

        ingestion_engine.dispose()


def test_stale_processing_payloads_are_recovered() -> None:
    source_id = uuid4()
    ingestion_run_id = uuid4()

    source_code = (
        f"TEST_CISA_RECOVERY_{uuid4().hex[:16]}"
    )

    retry_cve_id = (
        f"CVE-2099-"
        f"{uuid4().int % 1_000_000_000:09d}"
    )

    exhausted_cve_id = (
        f"CVE-2098-"
        f"{uuid4().int % 1_000_000_000:09d}"
    )

    owner_session_factory = (
        _create_owner_session_factory()
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
        retry_payload_id = _save_pending_payload(
            ingestion_session_factory=(
                ingestion_session_factory
            ),
            source_id=source_id,
            ingestion_run_id=ingestion_run_id,
            external_record_id=retry_cve_id,
            payload={
                "cveID": retry_cve_id,
                "vendorProject": "Retry Vendor",
                "product": "Retry Product",
                "vulnerabilityName": (
                    "Recoverable stale vulnerability"
                ),
                "dateAdded": "2026-07-20",
                "shortDescription": (
                    "A recoverable stale payload."
                ),
                "requiredAction": (
                    "Apply vendor mitigations."
                ),
                "dueDate": "2026-08-10",
                "knownRansomwareCampaignUse": (
                    "Unknown"
                ),
                "cwes": [
                    "CWE-79",
                ],
            },
        )

        exhausted_payload_id = _save_pending_payload(
            ingestion_session_factory=(
                ingestion_session_factory
            ),
            source_id=source_id,
            ingestion_run_id=ingestion_run_id,
            external_record_id=exhausted_cve_id,
            payload={
                "cveID": exhausted_cve_id,
                "vendorProject": (
                    "Exhausted Vendor"
                ),
                "product": (
                    "Exhausted Product"
                ),
                "vulnerabilityName": (
                    "Exhausted stale vulnerability"
                ),
                "dateAdded": "2026-07-20",
                "shortDescription": (
                    "A payload that exceeded "
                    "the retry limit."
                ),
                "requiredAction": (
                    "Apply vendor mitigations."
                ),
                "dueDate": "2026-08-10",
                "knownRansomwareCampaignUse": (
                    "Unknown"
                ),
                "cwes": [
                    "CWE-89",
                ],
            },
        )

        stale_started_at = (
            datetime.now(UTC)
            - timedelta(hours=1)
        )

        # Lease expirée, mais le payload peut
        # encore être repris.
        _force_processing_lease(
            ingestion_session_factory=(
                ingestion_session_factory
            ),
            payload_id=retry_payload_id,
            processing_started_at=(
                stale_started_at
            ),
            processing_attempts=1,
        )

        # Lease expirée avec le nombre maximal
        # de tentatives déjà atteint.
        _force_processing_lease(
            ingestion_session_factory=(
                ingestion_session_factory
            ),
            payload_id=exhausted_payload_id,
            processing_started_at=(
                stale_started_at
            ),
            processing_attempts=3,
        )

        service = CisaKevNormalizationService(
            unit_of_work=SqlAlchemyUnitOfWork(
                session_factory=(
                    ingestion_session_factory
                ),
            ),
            normalizer=CisaKevNormalizer(),
            lease_timeout=timedelta(
                minutes=15
            ),
            max_attempts=3,
        )

        result = service.process_pending(
            source_id=source_id,
            limit=10,
        )

        assert result.requeued == 1
        assert result.stale_failed == 1

        assert result.claimed == 1
        assert result.normalized == 1
        assert result.already_normalized == 0
        assert result.failed == 0

        with ingestion_session_factory() as session:
            retry_payload = session.get(
                SourcePayloadModel,
                retry_payload_id,
            )

            exhausted_payload = session.get(
                SourcePayloadModel,
                exhausted_payload_id,
            )

            normalized_rows = (
                session.execute(
                    select(
                        CisaKevVulnerabilityModel
                    ).where(
                        CisaKevVulnerabilityModel
                        .raw_payload_id
                        .in_(
                            [
                                retry_payload_id,
                                exhausted_payload_id,
                            ]
                        )
                    )
                )
                .scalars()
                .all()
            )

            assert retry_payload is not None

            assert (
                retry_payload.processing_status
                == "processed"
            )
            assert (
                retry_payload.processing_started_at
                is None
            )

            # Première réservation simulée :
            # attempts=1.
            # Nouvelle réservation après récupération :
            # attempts=2.
            assert (
                retry_payload.processing_attempts
                == 2
            )
            assert retry_payload.error_message is None

            assert exhausted_payload is not None

            assert (
                exhausted_payload.processing_status
                == "failed"
            )
            assert (
                exhausted_payload.processing_started_at
                is None
            )
            assert (
                exhausted_payload.processing_attempts
                == 3
            )

            assert (
                exhausted_payload.error_message
                == (
                    "Processing lease expired "
                    "after maximum attempts"
                )
            )

            # Seul le payload récupérable doit
            # être normalisé.
            assert len(normalized_rows) == 1

            normalized_row = normalized_rows[0]

            assert (
                normalized_row.raw_payload_id
                == retry_payload_id
            )
            assert (
                normalized_row.cve_id
                == retry_cve_id
            )

    finally:
        _delete_test_data(
            owner_session_factory=(
                owner_session_factory
            ),
            source_id=source_id,
        )

        ingestion_engine.dispose()
        