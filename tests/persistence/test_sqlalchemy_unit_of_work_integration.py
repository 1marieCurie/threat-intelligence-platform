from __future__ import annotations

from dotenv import load_dotenv

load_dotenv()

import os
from datetime import date
from uuid import UUID, uuid4

import pytest
from sqlalchemy import (
    create_engine,
    delete,
    select,
    text,
)
from sqlalchemy.orm import Session, sessionmaker

from application.ports.outbound.cisa_kev_vulnerability_repository import (
    CisaKevVulnerabilityData,
)
from application.ports.outbound.raw_payload_repository import (
    RawPayloadData,
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
                name="Unit of Work integration test",
            )
        )

        owner_session.commit()

    with ingestion_session_factory() as ingestion_session:
        ingestion_session.add(
            IngestionRunModel(
                id=ingestion_run_id,
                source_id=source_id,
                status="running",
            )
        )

        ingestion_session.commit()


def _build_vulnerability_data(
    *,
    raw_payload_id: UUID,
    cve_id: str,
) -> CisaKevVulnerabilityData:
    return CisaKevVulnerabilityData(
        raw_payload_id=raw_payload_id,
        cve_id=cve_id,
        vendor_project="Test Vendor",
        product="Test Product",
        vulnerability_name="Test vulnerability",
        date_added=date(
            2026,
            7,
            28,
        ),
        short_description=(
            "Normalized vulnerability description"
        ),
        required_action=(
            "Apply vendor mitigations."
        ),
        due_date=date(
            2026,
            8,
            18,
        ),
        known_ransomware_campaign_use=(
            "unknown"
        ),
        normalizer_version="1.0.0",
        cwes=(
            "CWE-79",
            "CWE-89",
        ),
        notes="Unit of Work integration test",
    )


def _delete_source(
    *,
    owner_session_factory: sessionmaker[Session],
    source_id: UUID,
) -> None:
    with owner_session_factory() as owner_session:
        owner_session.execute(
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

        # La table normalisée référence raw.source_payload
        # avec ON DELETE RESTRICT. Elle doit donc être
        # nettoyée en premier.
        owner_session.execute(
            delete(
                CisaKevVulnerabilityModel
            ).where(
                CisaKevVulnerabilityModel
                .raw_payload_id
                .in_(payload_ids)
            )
        )

        owner_session.execute(
            delete(
                SourcePayloadModel
            ).where(
                SourcePayloadModel
                .ingestion_run_id
                .in_(run_ids)
            )
        )

        owner_session.execute(
            delete(
                IngestionRunModel
            ).where(
                IngestionRunModel.source_id
                == source_id
            )
        )

        owner_session.execute(
            delete(
                SourceModel
            ).where(
                SourceModel.id == source_id
            )
        )

        owner_session.commit()


def test_commit_persists_payload_and_normalized_vulnerability() -> None:
    source_id = uuid4()
    ingestion_run_id = uuid4()
    source_code = (
        f"UOW_COMMIT_{uuid4().hex[:20]}"
    )
    cve_id = (
        f"CVE-2099-{uuid4().int % 1_000_000_000:09d}"
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
        owner_session_factory=owner_session_factory,
        ingestion_session_factory=(
            ingestion_session_factory
        ),
        source_id=source_id,
        ingestion_run_id=ingestion_run_id,
        source_code=source_code,
    )

    payload_id: UUID | None = None
    vulnerability_id: UUID | None = None

    try:
        unit_of_work = SqlAlchemyUnitOfWork(
            session_factory=(
                ingestion_session_factory
            ),
        )

        with unit_of_work:
            payload_id = (
                unit_of_work.raw_payloads.save(
                    RawPayloadData(
                        source_id=source_id,
                        ingestion_run_id=(
                            ingestion_run_id
                        ),
                        external_record_id=cve_id,
                        payload={
                            "cveID": cve_id,
                            "vendorProject": (
                                "Test Vendor"
                            ),
                            "product": "Test Product",
                        },
                        payload_hash="a" * 64,
                        http_status=200,
                    )
                )
            )

            vulnerability_id = (
                unit_of_work
                .cisa_kev_vulnerabilities
                .save(
                    _build_vulnerability_data(
                        raw_payload_id=payload_id,
                        cve_id=cve_id,
                    )
                )
            )

            unit_of_work.commit()

        with ingestion_session_factory() as session:
            persisted_payload = session.get(
                SourcePayloadModel,
                payload_id,
            )

            persisted_vulnerability = session.get(
                CisaKevVulnerabilityModel,
                vulnerability_id,
            )

            assert persisted_payload is not None
            assert (
                persisted_payload.external_record_id
                == cve_id
            )

            assert persisted_vulnerability is not None
            assert (
                persisted_vulnerability.raw_payload_id
                == payload_id
            )
            assert (
                persisted_vulnerability.cve_id
                == cve_id
            )
            assert (
                persisted_vulnerability.cwes
                == [
                    "CWE-79",
                    "CWE-89",
                ]
            )
            assert (
                persisted_vulnerability.normalizer_version
                == "1.0.0"
            )

    finally:
        _delete_source(
            owner_session_factory=(
                owner_session_factory
            ),
            source_id=source_id,
        )


def test_missing_commit_rolls_back_payload_and_normalized_vulnerability() -> None:
    source_id = uuid4()
    ingestion_run_id = uuid4()
    source_code = (
        f"UOW_ROLLBACK_{uuid4().hex[:18]}"
    )
    cve_id = (
        f"CVE-2099-{uuid4().int % 1_000_000_000:09d}"
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
        owner_session_factory=owner_session_factory,
        ingestion_session_factory=(
            ingestion_session_factory
        ),
        source_id=source_id,
        ingestion_run_id=ingestion_run_id,
        source_code=source_code,
    )

    payload_id: UUID | None = None
    vulnerability_id: UUID | None = None

    try:
        unit_of_work = SqlAlchemyUnitOfWork(
            session_factory=(
                ingestion_session_factory
            ),
        )

        with unit_of_work:
            payload_id = (
                unit_of_work.raw_payloads.save(
                    RawPayloadData(
                        source_id=source_id,
                        ingestion_run_id=(
                            ingestion_run_id
                        ),
                        external_record_id=cve_id,
                        payload={
                            "cveID": cve_id,
                        },
                        payload_hash="b" * 64,
                        http_status=200,
                    )
                )
            )

            vulnerability_id = (
                unit_of_work
                .cisa_kev_vulnerabilities
                .save(
                    _build_vulnerability_data(
                        raw_payload_id=payload_id,
                        cve_id=cve_id,
                    )
                )
            )

            # Aucun commit volontairement.

        with ingestion_session_factory() as session:
            assert (
                session.get(
                    SourcePayloadModel,
                    payload_id,
                )
                is None
            )

            assert (
                session.get(
                    CisaKevVulnerabilityModel,
                    vulnerability_id,
                )
                is None
            )

    finally:
        _delete_source(
            owner_session_factory=(
                owner_session_factory
            ),
            source_id=source_id,
        )


def test_exception_rolls_back_payload_and_normalized_vulnerability() -> None:
    source_id = uuid4()
    ingestion_run_id = uuid4()
    source_code = (
        f"UOW_EXCEPTION_{uuid4().hex[:17]}"
    )
    cve_id = (
        f"CVE-2099-{uuid4().int % 1_000_000_000:09d}"
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
        owner_session_factory=owner_session_factory,
        ingestion_session_factory=(
            ingestion_session_factory
        ),
        source_id=source_id,
        ingestion_run_id=ingestion_run_id,
        source_code=source_code,
    )

    payload_id: UUID | None = None
    vulnerability_id: UUID | None = None

    try:
        unit_of_work = SqlAlchemyUnitOfWork(
            session_factory=(
                ingestion_session_factory
            ),
        )

        with pytest.raises(
            RuntimeError,
            match="forced failure",
        ):
            with unit_of_work:
                payload_id = (
                    unit_of_work.raw_payloads.save(
                        RawPayloadData(
                            source_id=source_id,
                            ingestion_run_id=(
                                ingestion_run_id
                            ),
                            external_record_id=cve_id,
                            payload={
                                "cveID": cve_id,
                            },
                            payload_hash="c" * 64,
                            http_status=200,
                        )
                    )
                )

                vulnerability_id = (
                    unit_of_work
                    .cisa_kev_vulnerabilities
                    .save(
                        _build_vulnerability_data(
                            raw_payload_id=(
                                payload_id
                            ),
                            cve_id=cve_id,
                        )
                    )
                )

                raise RuntimeError(
                    "forced failure"
                )

        with ingestion_session_factory() as session:
            assert (
                session.get(
                    SourcePayloadModel,
                    payload_id,
                )
                is None
            )

            assert (
                session.get(
                    CisaKevVulnerabilityModel,
                    vulnerability_id,
                )
                is None
            )

    finally:
        _delete_source(
            owner_session_factory=(
                owner_session_factory
            ),
            source_id=source_id,
        )