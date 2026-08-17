from __future__ import annotations

import os
from collections.abc import Iterator
from datetime import (
    UTC,
    date,
    datetime,
    timedelta,
)
from pathlib import Path
from uuid import uuid4

import pytest
from dotenv import load_dotenv
from sqlalchemy import (
    create_engine,
    delete,
    event,
)
from sqlalchemy.engine import (
    Connection,
)
from sqlalchemy.orm import (
    Session,
    SessionTransaction,
    sessionmaker,
)
from sqlalchemy.pool import NullPool

from application.ports.outbound.cisa_kev_application_read_repository import (
    CisaKevApplicationKey,
)
from infrastructure.persistence.models.normalized import (
    CisaKevVulnerabilityModel,
)
from infrastructure.persistence.models.ops import (
    IngestionRunModel,
    SourceModel,
)
from infrastructure.persistence.models.raw import (
    IngestionRunPayloadModel,
    SourcePayloadModel,
)
from infrastructure.persistence.sqlalchemy.repositories.cisa_kev_application_read_repository import (
    SqlAlchemyCisaKevApplicationReadRepository,
)


PROJECT_ROOT = Path(
    __file__
).resolve().parents[2]

load_dotenv(
    dotenv_path=PROJECT_ROOT / ".env",
    override=False,
)

pytestmark = pytest.mark.integration


T1 = datetime(
    2026,
    8,
    17,
    12,
    0,
    tzinfo=UTC,
)

T2 = T1 + timedelta(
    hours=1
)


class OwnerSession(Session):
    pass


@event.listens_for(
    OwnerSession,
    "after_begin",
)
def _set_owner_role(
    session: Session,
    transaction: SessionTransaction,
    connection: Connection,
) -> None:
    del session
    del transaction

    connection.exec_driver_sql(
        "SET LOCAL ROLE threat_intel_owner"
    )


@pytest.fixture
def owner_session_factory(
) -> Iterator[
    sessionmaker[Session]
]:
    database_url = os.environ.get(
        "MIGRATION_DATABASE_URL"
    )

    if not database_url:
        raise RuntimeError(
            "MIGRATION_DATABASE_URL "
            "is not defined"
        )

    engine = create_engine(
        database_url,
        pool_pre_ping=True,
        poolclass=NullPool,
        future=True,
    )

    factory: sessionmaker[Session] = (
        sessionmaker(
            bind=engine,
            class_=OwnerSession,
            autoflush=False,
            expire_on_commit=False,
        )
    )

    try:
        yield factory

    finally:
        engine.dispose()


def test_reader_uses_only_latest_completed_cisa_snapshot(
    owner_session_factory: sessionmaker[
        Session
    ],
) -> None:
    source_id = uuid4()

    first_run_id = uuid4()
    second_run_id = uuid4()

    raw_payload_id = uuid4()
    normalized_id = uuid4()

    source_code = (
        "CISA_KEV_TEST_"
        f"{uuid4().hex[:20]}"
    )

    cve_id = (
        "CVE-2099-"
        f"{100000 + uuid4().int % 899999}"
    )

    try:
        # -------------------------------------------------
        # Snapshot 1 :
        # la CVE est présente dans CISA KEV.
        # -------------------------------------------------
        with owner_session_factory() as session:
            # Important :
            # Source doit exister physiquement avant
            # IngestionRun à cause de la FK.
            source = SourceModel(
                id=source_id,
                code=source_code,
                name=(
                    "CISA KEV application "
                    "reader integration test"
                ),
            )

            session.add(
                source
            )

            session.flush()

            first_run = IngestionRunModel(
                id=first_run_id,
                source_id=source_id,
                status="completed",
                started_at=T1,
                finished_at=T1,
                records_received=1,
                records_succeeded=1,
                records_failed=0,
            )

            session.add(
                first_run
            )

            session.flush()

            raw_payload = SourcePayloadModel(
                id=raw_payload_id,
                source_id=source_id,
                ingestion_run_id=(
                    first_run_id
                ),
                external_record_id=cve_id,
                retrieved_at=T1,
                request_url=(
                    "https://example.test/cisa"
                ),
                http_status=200,
                payload={
                    "cveID": cve_id,
                    "vendorProject": (
                        "Microsoft"
                    ),
                    "product": (
                        "Microsoft Edge"
                    ),
                },
                payload_hash="a" * 64,
                processing_status=(
                    "processed"
                ),
                processing_attempts=1,
            )

            session.add(
                raw_payload
            )

            session.flush()

            run_payload_link = (
                IngestionRunPayloadModel(
                    ingestion_run_id=(
                        first_run_id
                    ),
                    raw_payload_id=(
                        raw_payload_id
                    ),
                    observed_at=T1,
                )
            )

            session.add(
                run_payload_link
            )

            normalized_vulnerability = (
                CisaKevVulnerabilityModel(
                    id=normalized_id,
                    raw_payload_id=(
                        raw_payload_id
                    ),
                    cve_id=cve_id,
                    vendor_project=(
                        "Microsoft"
                    ),
                    product=(
                        "Microsoft Edge"
                    ),
                    vulnerability_name=(
                        "Integration test "
                        "vulnerability"
                    ),
                    date_added=date(
                        2026,
                        8,
                        1,
                    ),
                    short_description=(
                        "Integration test"
                    ),
                    required_action=(
                        "Apply mitigations."
                    ),
                    due_date=date(
                        2026,
                        8,
                        22,
                    ),
                    known_ransomware_campaign_use=(
                        "unknown"
                    ),
                    notes=None,
                    cwes=[],
                    normalizer_version=(
                        "1.0.0"
                    ),
                    normalized_at=T1,
                )
            )

            session.add(
                normalized_vulnerability
            )

            session.commit()

        # -------------------------------------------------
        # Vérification snapshot 1 :
        # l'application est actuellement dans KEV.
        # -------------------------------------------------
        with owner_session_factory() as session:
            repository = (
                SqlAlchemyCisaKevApplicationReadRepository(
                    session=session,
                    source_code=source_code,
                )
            )

            candidates = (
                repository.find_candidates(
                    application_keys=[
                        CisaKevApplicationKey(
                            vendor_project=(
                                "microsoft"
                            ),
                            product=(
                                "microsoft edge"
                            ),
                        )
                    ]
                )
            )

            assert len(
                candidates
            ) == 1

            assert (
                candidates[0].cve_id
                == cve_id
            )

            assert (
                candidates[0]
                .normalized_vendor_project
                == "microsoft"
            )

            assert (
                candidates[0]
                .normalized_product
                == "microsoft edge"
            )

        # -------------------------------------------------
        # Snapshot 2 :
        # nouveau snapshot CISA complet.
        #
        # Cette CVE n'y apparaît plus.
        # -------------------------------------------------
        with owner_session_factory() as session:
            second_run = IngestionRunModel(
                id=second_run_id,
                source_id=source_id,
                status="completed",
                started_at=T2,
                finished_at=T2,
                records_received=0,
                records_succeeded=0,
                records_failed=0,
            )

            session.add(
                second_run
            )

            session.commit()

        # -------------------------------------------------
        # Vérification snapshot 2 :
        #
        # La ligne normalized existe toujours,
        # mais elle ne doit plus être considérée
        # comme KEV courante.
        # -------------------------------------------------
        with owner_session_factory() as session:
            persisted_old_observation = (
                session.get(
                    CisaKevVulnerabilityModel,
                    normalized_id,
                )
            )

            assert (
                persisted_old_observation
                is not None
            )

            repository = (
                SqlAlchemyCisaKevApplicationReadRepository(
                    session=session,
                    source_code=source_code,
                )
            )

            candidates = (
                repository.find_candidates(
                    application_keys=[
                        CisaKevApplicationKey(
                            vendor_project=(
                                "microsoft"
                            ),
                            product=(
                                "microsoft edge"
                            ),
                        )
                    ]
                )
            )

            # Élément essentiel du test :
            #
            # l'ancienne observation existe encore
            # dans normalized.cisa_kev_vulnerability,
            # mais elle n'appartient pas au dernier
            # snapshot complet.
            assert candidates == ()

    finally:
        # -------------------------------------------------
        # Cleanup explicite dans l'ordre des FK.
        # -------------------------------------------------
        with owner_session_factory() as session:
            session.execute(
                delete(
                    CisaKevVulnerabilityModel
                ).where(
                    CisaKevVulnerabilityModel.id
                    == normalized_id
                )
            )

            session.execute(
                delete(
                    IngestionRunPayloadModel
                ).where(
                    IngestionRunPayloadModel
                    .ingestion_run_id
                    .in_(
                        (
                            first_run_id,
                            second_run_id,
                        )
                    )
                )
            )

            session.execute(
                delete(
                    SourcePayloadModel
                ).where(
                    SourcePayloadModel.id
                    == raw_payload_id
                )
            )

            session.execute(
                delete(
                    IngestionRunModel
                ).where(
                    IngestionRunModel.id
                    .in_(
                        (
                            first_run_id,
                            second_run_id,
                        )
                    )
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