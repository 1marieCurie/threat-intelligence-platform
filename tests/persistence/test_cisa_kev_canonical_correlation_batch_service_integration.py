from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(
    __file__
).resolve().parents[2]

load_dotenv(
    dotenv_path=PROJECT_ROOT / ".env",
    override=False,
)


import os
from datetime import (
    UTC,
    date,
    datetime,
)
from uuid import (
    UUID,
    uuid4,
)

import pytest
from sqlalchemy import (
    create_engine,
    delete,
    func,
    select,
    text,
)
from sqlalchemy.orm import (
    Session,
    sessionmaker,
)

from application.models.cisa_kev_canonical_source_record import (
    CisaKevCanonicalCursor,
)
from application.services.canonical_cwe_association_builder import (
    CanonicalCWEAssociationBuilder,
)
from application.services.canonical_cwe_enrichment_service import (
    CanonicalCWEEnrichmentService,
)
from application.services.canonical_vulnerability_correlation_service import (
    CanonicalVulnerabilityCorrelationService,
)
from application.services.cisa_kev_canonical_correlation_batch_service import (
    CisaKevCanonicalCorrelationBatchService,
)
from application.services.cisa_kev_canonical_observation_builder import (
    CisaKevCanonicalObservationBuilder,
)
from application.services.cwe_lookup_service import (
    CWELookupService,
)
from infrastructure.persistence.models.canonical import (
    CanonicalVulnerabilityIdentifierModel,
    CanonicalVulnerabilityModel,
    CanonicalVulnerabilityWeaknessModel,
)
from infrastructure.persistence.models.normalized import (
    CisaKevVulnerabilityModel,
    CWEWeaknessModel,
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
from infrastructure.persistence.sqlalchemy.readers.cisa_kev_canonical_source import (
    SqlAlchemyCisaKevCanonicalSource,
)


pytestmark = pytest.mark.integration


def _payload_hash() -> str:
    return (
        uuid4().hex
        + uuid4().hex
    )


def _build_correlation_service(
    *,
    session_factory: sessionmaker[Session],
) -> CanonicalVulnerabilityCorrelationService:
    return CanonicalVulnerabilityCorrelationService(
        unit_of_work=SqlAlchemyUnitOfWork(
            session_factory=session_factory,
        ),
    )


def _build_cwe_enrichment_service(
    *,
    session_factory: sessionmaker[Session],
) -> CanonicalCWEEnrichmentService:
    return CanonicalCWEEnrichmentService(
        cwe_lookup=CWELookupService(
            unit_of_work=SqlAlchemyUnitOfWork(
                session_factory=session_factory,
            ),
        ),
        builder=(
            CanonicalCWEAssociationBuilder()
        ),
        unit_of_work=SqlAlchemyUnitOfWork(
            session_factory=session_factory,
        ),
    )


def test_correlates_and_enriches_cisa_kev_with_real_postgresql(
) -> None:
    database_url = os.environ.get(
        "MIGRATION_DATABASE_URL"
    )

    if not database_url:
        raise RuntimeError(
            "MIGRATION_DATABASE_URL "
            "is not defined"
        )

    source_id = uuid4()
    ingestion_run_id = uuid4()
    raw_payload_id = uuid4()
    normalized_record_id = uuid4()

    source_code = (
        "TEST_CISA_CWE_"
        f"{uuid4().hex[:16].upper()}"
    )

    cve_serial = (
        100_000_000_000_000_000
        + uuid4().int
        % 800_000_000_000_000_000
    )

    cve_id = (
        f"CVE-9999-{cve_serial}"
    )

    cwe_number = (
        100_000
        + uuid4().int
        % 800_000
    )

    official_cwe_id = (
        f"CWE-{cwe_number}"
    )

    missing_cwe_id = (
        f"CWE-{cwe_number + 1_000_000}"
    )

    observed_at = datetime(
        2026,
        8,
        5,
        12,
        0,
        tzinfo=UTC,
    )

    date_added = date(
        2026,
        8,
        5,
    )

    initial_cursor = CisaKevCanonicalCursor(
        cve_id=cve_id,
        normalized_record_id=UUID(
            int=0
        ),
    )

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

            session.add(
                SourceModel(
                    id=source_id,
                    code=source_code,
                    name=(
                        "CISA canonical CWE "
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

            session.add(
                SourcePayloadModel(
                    id=raw_payload_id,
                    source_id=source_id,
                    ingestion_run_id=(
                        ingestion_run_id
                    ),
                    external_record_id=cve_id,
                    payload={
                        "cveID": cve_id,
                    },
                    payload_hash=_payload_hash(),
                    http_status=200,
                    processing_status="processed",
                )
            )

            session.flush()

            session.add(
                CWEWeaknessModel(
                    cwe_id=official_cwe_id,
                    name=(
                        "Integration test CWE"
                    ),
                    description=(
                        "Temporary official CWE "
                        "catalogue fixture."
                    ),
                )
            )

            session.add(
                CisaKevVulnerabilityModel(
                    id=normalized_record_id,
                    raw_payload_id=raw_payload_id,
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
                    date_added=date_added,
                    short_description=(
                        "Temporary integration "
                        "test vulnerability."
                    ),
                    required_action=(
                        "Apply the vendor update."
                    ),
                    due_date=date(
                        2026,
                        8,
                        20,
                    ),
                    known_ransomware_campaign_use=(
                        "unknown"
                    ),
                    notes=None,
                    cwes=[
                        official_cwe_id,
                        missing_cwe_id,
                    ],
                    normalizer_version="1.0.0",
                    normalized_at=observed_at,
                )
            )

            session.commit()

        correlation_service = (
            _build_correlation_service(
                session_factory=(
                    ingestion_session_factory
                ),
            )
        )

        cwe_enrichment_service = (
            _build_cwe_enrichment_service(
                session_factory=(
                    ingestion_session_factory
                ),
            )
        )

        with ingestion_session_factory() as session:
            batch_service = (
                CisaKevCanonicalCorrelationBatchService(
                    source=(
                        SqlAlchemyCisaKevCanonicalSource(
                            session=session,
                        )
                    ),
                    builder=(
                        CisaKevCanonicalObservationBuilder()
                    ),
                    correlation_service=(
                        correlation_service
                    ),
                    cwe_enrichment_service=(
                        cwe_enrichment_service
                    ),
                )
            )

            result = batch_service.process_batch(
                after_cursor=initial_cursor,
                limit=1,
            )

            assert result.records_read == 1

            assert result.next_cursor == (
                CisaKevCanonicalCursor(
                    cve_id=cve_id,
                    normalized_record_id=(
                        normalized_record_id
                    ),
                )
            )

            assert (
                result.correlation.created
                == 1
            )

            assert (
                result.correlation.persisted
                == 1
            )

            assert (
                result.cwe_enrichment
                .records_received
                == 1
            )

            assert (
                result.cwe_enrichment
                .records_enriched
                == 1
            )

            assert (
                result.cwe_enrichment
                .requested_unique_cwe_ids
                == 2
            )

            assert (
                result.cwe_enrichment
                .found_unique_cwe_ids
                == 1
            )

            assert (
                result.cwe_enrichment
                .missing_cwe_ids
                == (
                    missing_cwe_id,
                )
            )

            assert (
                result.cwe_enrichment.persisted
                == 1
            )

            aggregate = (
                result
                .correlation
                .aggregates[0]
            )

            assert (
                aggregate.status
                == "active"
            )

            assert (
                aggregate
                .primary_identifier
                .key
                == (
                    "CVE",
                    cve_id,
                )
            )

            replay = (
                batch_service.process_batch(
                    after_cursor=initial_cursor,
                    limit=1,
                )
            )

            assert (
                replay.correlation.created
                == 0
            )

            assert (
                replay.correlation.updated
                == 1
            )

            assert (
                replay.cwe_enrichment.persisted
                == 1
            )

        with ingestion_session_factory() as session:
            associations = (
                session.execute(
                    select(
                        CanonicalVulnerabilityWeaknessModel
                    )
                    .where(
                        CanonicalVulnerabilityWeaknessModel
                        .source
                        == "cisa_kev"
                    )
                    .where(
                        CanonicalVulnerabilityWeaknessModel
                        .source_record_key
                        == cve_id
                    )
                    .where(
                        CanonicalVulnerabilityWeaknessModel
                        .cwe_id
                        == official_cwe_id
                    )
                )
                .scalars()
                .all()
            )

            assert len(associations) == 1

            association = associations[0]

            assert (
                association.vulnerability_id
                == aggregate.id
            )

            assert (
                association.normalized_record_id
                == str(
                    normalized_record_id
                )
            )

            assert (
                association.observed_at
                == observed_at
            )

            assert (
                association.last_observed_at
                == observed_at
            )

            assert (
                association.source_modified_at
                is None
            )

            row_count = session.execute(
                select(
                    func.count()
                )
                .select_from(
                    CanonicalVulnerabilityWeaknessModel
                )
                .where(
                    CanonicalVulnerabilityWeaknessModel
                    .source
                    == "cisa_kev"
                )
                .where(
                    CanonicalVulnerabilityWeaknessModel
                    .source_record_key
                    == cve_id
                )
                .where(
                    CanonicalVulnerabilityWeaknessModel
                    .cwe_id
                    == official_cwe_id
                )
            ).scalar_one()

            assert row_count == 1

    finally:
        with owner_session_factory() as session:
            session.execute(
                text(
                    "SET ROLE threat_intel_owner"
                )
            )

            session.execute(
                delete(
                    CanonicalVulnerabilityWeaknessModel
                ).where(
                    CanonicalVulnerabilityWeaknessModel
                    .source
                    == "cisa_kev"
                ).where(
                    CanonicalVulnerabilityWeaknessModel
                    .source_record_key
                    == cve_id
                )
            )

            canonical_ids = (
                session.execute(
                    select(
                        CanonicalVulnerabilityIdentifierModel
                        .vulnerability_id
                    )
                    .where(
                        CanonicalVulnerabilityIdentifierModel
                        .value
                        == cve_id
                    )
                )
                .scalars()
                .all()
            )

            if canonical_ids:
                session.execute(
                    delete(
                        CanonicalVulnerabilityModel
                    ).where(
                        CanonicalVulnerabilityModel
                        .id
                        .in_(
                            canonical_ids
                        )
                    )
                )

            session.execute(
                delete(
                    CisaKevVulnerabilityModel
                ).where(
                    CisaKevVulnerabilityModel.id
                    == normalized_record_id
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

            session.execute(
                delete(
                    CWEWeaknessModel
                ).where(
                    CWEWeaknessModel.cwe_id
                    == official_cwe_id
                )
            )

            session.commit()

        ingestion_engine.dispose()
        owner_engine.dispose()