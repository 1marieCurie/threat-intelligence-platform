from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)

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
from application.services.canonical_vulnerability_correlation_service import (
    CanonicalVulnerabilityCorrelationService,
)
from application.services.cisa_kev_canonical_correlation_batch_service import (
    CisaKevCanonicalCorrelationBatchService,
)
from application.services.cisa_kev_canonical_observation_builder import (
    CisaKevCanonicalObservationBuilder,
)
from infrastructure.persistence.models.canonical import (
    CanonicalVulnerabilityEvidenceModel,
    CanonicalVulnerabilityIdentifierModel,
    CanonicalVulnerabilityModel,
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
from infrastructure.persistence.sqlalchemy.readers.cisa_kev_canonical_source import (
    SqlAlchemyCisaKevCanonicalSource,
)


pytestmark = pytest.mark.integration


def test_correlates_cisa_kev_batches_with_real_postgresql(
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

    source_code = (
        "TEST_CISA_CANON_"
        f"{uuid4().hex[:20]}"
    )

    serial = (
        8_000_000_000_000_000_000
        + uuid4().int
        % 100_000_000_000_000_000
    )

    duplicate_cve = (
        f"CVE-9998-{serial}"
    )

    second_cve = (
        f"CVE-9999-{serial}"
    )

    cve_ids = [
        duplicate_cve,
        second_cve,
    ]

    raw_payload_ids = [
        uuid4()
        for _ in range(3)
    ]

    uuid_base = (
        uuid4().int
        & ~0xFF
    )

    normalized_ids = [
        UUID(
            int=uuid_base + index
        )
        for index in range(1, 4)
    ]

    duplicate_ids = sorted(
        normalized_ids[:2],
        key=str,
    )

    normalized_ids = [
        duplicate_ids[0],
        duplicate_ids[1],
        normalized_ids[2],
    ]

    initial_cursor = CisaKevCanonicalCursor(
        cve_id=(
            f"CVE-9998-{serial - 1}"
        ),
        normalized_record_id=UUID(
            int=(1 << 128) - 1
        ),
    )

    canonical_ids: set[UUID] = set()

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
                        "CISA canonical "
                        "integration test"
                    ),
                )
            )

            # Persister explicitement le parent avant
            # d'insérer l'ingestion run qui le référence.
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
                        id=raw_payload_id,
                        source_id=source_id,
                        ingestion_run_id=(
                            ingestion_run_id
                        ),
                        external_record_id=(
                            f"{cve_id}-{index}"
                        ),
                        payload={
                            "cveID": cve_id,
                        },
                        payload_hash=(
                            f"{index + 1:064x}"
                        ),
                        http_status=200,
                        processing_status=(
                            "processed"
                        ),
                    )
                    for (
                        index,
                        (
                            raw_payload_id,
                            cve_id,
                        ),
                    )
                    in enumerate(
                        zip(
                            raw_payload_ids,
                            [
                                duplicate_cve,
                                duplicate_cve,
                                second_cve,
                            ],
                            strict=True,
                        )
                    )
                ]
            )

            session.flush()

            session.add_all(
                [
                    CisaKevVulnerabilityModel(
                        id=normalized_ids[index],
                        raw_payload_id=(
                            raw_payload_ids[index]
                        ),
                        cve_id=cve_id,
                        vendor_project=(
                            "Test Vendor"
                        ),
                        product="Test Product",
                        vulnerability_name=(
                            "Test vulnerability"
                        ),
                        date_added=date(
                            2026,
                            8,
                            2 + index,
                        ),
                        short_description=(
                            "Test description"
                        ),
                        required_action=(
                            "Apply mitigations."
                        ),
                        due_date=date(
                            2026,
                            9,
                            1,
                        ),
                        known_ransomware_campaign_use=(
                            "unknown"
                        ),
                        notes=None,
                        cwes=[],
                        normalizer_version="1.0.0",
                        normalized_at=datetime(
                            2026,
                            8,
                            2 + index,
                            12,
                            0,
                            tzinfo=UTC,
                        ),
                    )
                    for index, cve_id
                    in enumerate(
                        [
                            duplicate_cve,
                            duplicate_cve,
                            second_cve,
                        ]
                    )
                ]
            )

            session.commit()

        correlation_service = (
            CanonicalVulnerabilityCorrelationService(
                unit_of_work=(
                    SqlAlchemyUnitOfWork(
                        session_factory=(
                            ingestion_session_factory
                        ),
                    )
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
                )
            )

            first_batch = (
                batch_service.process_batch(
                    after_cursor=initial_cursor,
                    limit=2,
                )
            )

            assert first_batch.records_read == 2

            assert first_batch.next_cursor == (
                CisaKevCanonicalCursor(
                    cve_id=duplicate_cve,
                    normalized_record_id=(
                        normalized_ids[1]
                    ),
                )
            )

            assert (
                first_batch.source_exhausted
                is False
            )

            assert (
                first_batch
                .correlation
                .observations_received
                == 2
            )

            # Les deux lignes possèdent le même CVE
            # et forment donc un seul agrégat.
            assert (
                first_batch
                .correlation
                .components_built
                == 1
            )

            assert (
                first_batch
                .correlation
                .created
                == 1
            )

            assert (
                first_batch
                .correlation
                .persisted
                == 1
            )

            first_aggregate = (
                first_batch
                .correlation
                .aggregates[0]
            )

            canonical_ids.add(
                first_aggregate.id
            )

            assert (
                first_aggregate.status
                == "active"
            )

            assert len(
                first_aggregate.evidences
            ) == 1

            merged_evidence = (
                first_aggregate.evidences[0]
            )

            assert (
                merged_evidence.observed_at
                == datetime(
                    2026,
                    8,
                    2,
                    12,
                    0,
                    tzinfo=UTC,
                )
            )

            assert (
                merged_evidence.last_observed_at
                == datetime(
                    2026,
                    8,
                    3,
                    12,
                    0,
                    tzinfo=UTC,
                )
            )

            assert (
                merged_evidence
                .normalized_record_id
                == str(
                    normalized_ids[1]
                )
            )

            second_batch = (
                batch_service.process_batch(
                    after_cursor=(
                        first_batch.next_cursor
                    ),
                    limit=2,
                )
            )

            assert second_batch.records_read == 1

            assert second_batch.next_cursor == (
                CisaKevCanonicalCursor(
                    cve_id=second_cve,
                    normalized_record_id=(
                        normalized_ids[2]
                    ),
                )
            )

            assert (
                second_batch.source_exhausted
                is True
            )

            assert (
                second_batch
                .correlation
                .created
                == 1
            )

            canonical_ids.update(
                aggregate.id
                for aggregate
                in second_batch
                .correlation
                .aggregates
            )

            replay = (
                batch_service.process_batch(
                    after_cursor=initial_cursor,
                    limit=2,
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
                replay.correlation.persisted
                == 1
            )

        with ingestion_session_factory() as session:
            identifiers = (
                session.execute(
                    select(
                        CanonicalVulnerabilityIdentifierModel
                    )
                    .where(
                        CanonicalVulnerabilityIdentifierModel
                        .namespace
                        == "CVE"
                    )
                    .where(
                        CanonicalVulnerabilityIdentifierModel
                        .value
                        .in_(cve_ids)
                    )
                )
                .scalars()
                .all()
            )

            assert len(identifiers) == 2

            assert {
                identifier.value
                for identifier in identifiers
            } == set(cve_ids)

            assert all(
                identifier.is_primary
                for identifier in identifiers
            )

            evidences = (
                session.execute(
                    select(
                        CanonicalVulnerabilityEvidenceModel
                    )
                    .where(
                        CanonicalVulnerabilityEvidenceModel
                        .source
                        == "cisa_kev"
                    )
                    .where(
                        CanonicalVulnerabilityEvidenceModel
                        .source_record_key
                        .in_(cve_ids)
                    )
                )
                .scalars()
                .all()
            )

            assert len(evidences) == 2

            assert all(
                evidence.evidence_type
                == (
                    "known_exploited_"
                    "vulnerability"
                )
                for evidence in evidences
            )

            assert all(
                evidence.correlation_rule
                == "exact_cve"
                for evidence in evidences
            )

            vulnerabilities = (
                session.execute(
                    select(
                        CanonicalVulnerabilityModel
                    )
                    .where(
                        CanonicalVulnerabilityModel
                        .id
                        .in_(canonical_ids)
                    )
                )
                .scalars()
                .all()
            )

            assert len(vulnerabilities) == 2

            assert all(
                vulnerability.status
                == "active"
                for vulnerability
                in vulnerabilities
            )

    finally:
        with owner_session_factory() as session:
            session.execute(
                text(
                    "SET ROLE threat_intel_owner"
                )
            )

            if canonical_ids:
                session.execute(
                    delete(
                        CanonicalVulnerabilityModel
                    ).where(
                        CanonicalVulnerabilityModel
                        .id
                        .in_(canonical_ids)
                    )
                )

            session.execute(
                delete(
                    CisaKevVulnerabilityModel
                ).where(
                    CisaKevVulnerabilityModel
                    .id
                    .in_(normalized_ids)
                )
            )

            session.execute(
                delete(
                    SourcePayloadModel
                ).where(
                    SourcePayloadModel
                    .id
                    .in_(raw_payload_ids)
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