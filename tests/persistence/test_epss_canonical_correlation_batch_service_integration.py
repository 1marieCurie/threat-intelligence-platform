from __future__ import annotations

import os
from datetime import (
    UTC,
    date,
    datetime,
)
from pathlib import Path
from uuid import (
    UUID,
    uuid4,
)

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

from application.services.canonical_vulnerability_correlation_service import (
    CanonicalVulnerabilityCorrelationService,
)
from application.services.epss_canonical_correlation_batch_service import (
    EPSSCanonicalCorrelationBatchService,
)
from application.services.epss_canonical_observation_builder import (
    EPSSCanonicalObservationBuilder,
)
from infrastructure.persistence.models.canonical import (
    CanonicalVulnerabilityEvidenceModel,
    CanonicalVulnerabilityIdentifierModel,
    CanonicalVulnerabilityModel,
)
from infrastructure.persistence.models.normalized import (
    EPSSScoreModel,
)
from infrastructure.persistence.sqlalchemy import (
    SqlAlchemyUnitOfWork,
    create_ingestion_engine,
    create_session_factory,
)
from infrastructure.persistence.sqlalchemy.readers.epss_canonical_source import (
    SqlAlchemyEPSSCanonicalSource,
)


pytestmark = pytest.mark.integration


def test_correlates_epss_batches_with_real_postgresql(
) -> None:
    database_url = os.environ.get(
        "MIGRATION_DATABASE_URL"
    )

    if not database_url:
        raise RuntimeError(
            "MIGRATION_DATABASE_URL "
            "is not defined"
        )

    base_serial = (
        8_000_000_000_000_000_000
        + uuid4().int
        % 100_000_000_000_000_000
    )

    cve_ids = [
        (
            "CVE-9999-"
            f"{base_serial + index}"
        )
        for index in range(3)
    ]

    initial_cursor = (
        "CVE-9999-"
        f"{base_serial - 1}"
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

            session.add_all(
                [
                    EPSSScoreModel(
                        cve_id=cve_id,
                        epss_score=(
                            0.20
                            + index * 0.10
                        ),
                        percentile=(
                            0.70
                            + index * 0.05
                        ),
                        score_date=date(
                            2026,
                            8,
                            2 + index,
                        ),
                        api_version="v1",
                        synchronized_at=datetime(
                            2026,
                            8,
                            2 + index,
                            12,
                            0,
                            tzinfo=UTC,
                        ),
                    )
                    for index, cve_id
                    in enumerate(cve_ids)
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
                EPSSCanonicalCorrelationBatchService(
                    source=(
                        SqlAlchemyEPSSCanonicalSource(
                            session=session,
                        )
                    ),
                    builder=(
                        EPSSCanonicalObservationBuilder()
                    ),
                    correlation_service=(
                        correlation_service
                    ),
                )
            )

            first_batch = (
                batch_service.process_batch(
                    after_cve_id=(
                        initial_cursor
                    ),
                    limit=2,
                )
            )

            assert first_batch.records_read == 2

            assert first_batch.next_cursor == (
                cve_ids[1]
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

            assert (
                first_batch
                .correlation
                .created
                == 2
            )

            assert (
                first_batch
                .correlation
                .updated
                == 0
            )

            canonical_ids.update(
                aggregate.id
                for aggregate
                in first_batch
                .correlation
                .aggregates
            )

            second_batch = (
                batch_service.process_batch(
                    after_cve_id=(
                        first_batch.next_cursor
                    ),
                    limit=2,
                )
            )

            assert second_batch.records_read == 1

            assert second_batch.next_cursor == (
                cve_ids[2]
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
                    after_cve_id=(
                        initial_cursor
                    ),
                    limit=2,
                )
            )

            assert replay.records_read == 2

            assert (
                replay.correlation.created
                == 0
            )

            assert (
                replay.correlation.updated
                == 2
            )

            assert (
                replay.correlation.persisted
                == 2
            )

        with ingestion_session_factory() as session:
            identifier_rows = (
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

            assert len(identifier_rows) == 3

            assert {
                row.value
                for row in identifier_rows
            } == set(cve_ids)

            assert all(
                row.is_primary
                for row in identifier_rows
            )

            evidence_rows = (
                session.execute(
                    select(
                        CanonicalVulnerabilityEvidenceModel
                    )
                    .where(
                        CanonicalVulnerabilityEvidenceModel
                        .source
                        == "epss"
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

            assert len(evidence_rows) == 3

            assert {
                row.source_record_key
                for row in evidence_rows
            } == set(cve_ids)

            assert all(
                row.evidence_type
                == "epss_snapshot"
                for row in evidence_rows
            )

            assert all(
                row.correlation_rule
                == "exact_cve"
                for row in evidence_rows
            )

            vulnerability_rows = (
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

            assert len(vulnerability_rows) == 3

            assert all(
                row.status == "provisional"
                for row in vulnerability_rows
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
                    EPSSScoreModel
                ).where(
                    EPSSScoreModel
                    .cve_id
                    .in_(cve_ids)
                )
            )

            session.commit()

        ingestion_engine.dispose()
        owner_engine.dispose()