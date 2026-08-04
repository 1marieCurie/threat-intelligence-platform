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

from application.models.github_advisory_canonical_source_record import (
    GitHubAdvisoryCanonicalCursor,
)
from application.services.canonical_vulnerability_correlation_service import (
    CanonicalVulnerabilityCorrelationService,
)
from application.services.github_advisory_canonical_correlation_batch_service import (
    GitHubAdvisoryCanonicalCorrelationBatchService,
)
from application.services.github_advisory_canonical_observation_builder import (
    GitHubAdvisoryCanonicalObservationBuilder,
)
from infrastructure.persistence.models.canonical import (
    CanonicalVulnerabilityEvidenceModel,
    CanonicalVulnerabilityIdentifierModel,
    CanonicalVulnerabilityModel,
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
from infrastructure.persistence.sqlalchemy.readers.github_advisory_canonical_source import (
    SqlAlchemyGitHubAdvisoryCanonicalSource,
)


pytestmark = pytest.mark.integration


def test_correlates_github_advisory_batches_with_real_postgresql(
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
        "TEST_GHSA_CANON_"
        f"{uuid4().hex[:20]}"
    )

    token = uuid4().hex[:8]

    active_storage_ghsa = (
    "GHSA-zzzz-zzzz-zzzy"
)

    withdrawn_storage_ghsa = (
        "GHSA-zzzz-zzzz-zzzz"
    )

    active_canonical_ghsa = (
        active_storage_ghsa.upper()
    )

    withdrawn_canonical_ghsa = (
        withdrawn_storage_ghsa.upper()
    )

    serial = (
        8_000_000_000_000_000_000
        + uuid4().int
        % 100_000_000_000_000_000
    )

    cve_id = f"CVE-9999-{serial}"

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

    initial_cursor = (
    GitHubAdvisoryCanonicalCursor(
        ghsa_id=active_storage_ghsa,
        normalized_record_id=UUID(
            int=0
        ),
    )
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
                        "GitHub advisory canonical "
                        "integration test"
                    ),
                )
            )

            # SourceModel et IngestionRunModel ne
            # déclarent pas de relation ORM explicite.
            session.flush()

            session.add(
                IngestionRunModel(
                    id=ingestion_run_id,
                    source_id=source_id,
                    status="completed",
                )
            )

            session.flush()

            storage_ghsa_ids = [
                active_storage_ghsa,
                active_storage_ghsa,
                withdrawn_storage_ghsa,
            ]

            session.add_all(
                [
                    SourcePayloadModel(
                        id=raw_payload_id,
                        source_id=source_id,
                        ingestion_run_id=(
                            ingestion_run_id
                        ),
                        external_record_id=(
                            f"{ghsa_id}-{index}"
                        ),
                        payload={
                            "ghsa_id": ghsa_id,
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
                            ghsa_id,
                        ),
                    )
                    in enumerate(
                        zip(
                            raw_payload_ids,
                            storage_ghsa_ids,
                            strict=True,
                        )
                    )
                ]
            )

            session.flush()

            session.add_all(
                [
                    GitHubAdvisoryVulnerabilityModel(
                        id=normalized_ids[0],
                        raw_payload_id=(
                            raw_payload_ids[0]
                        ),
                        ghsa_id=active_storage_ghsa,
                        cve_id=None,
                        advisory_type="reviewed",
                        severity="HIGH",
                        summary="First snapshot",
                        description=None,
                        published_at=datetime(
                            2026,
                            8,
                            1,
                            10,
                            0,
                            tzinfo=UTC,
                        ),
                        updated_at=datetime(
                            2026,
                            8,
                            2,
                            11,
                            0,
                            tzinfo=UTC,
                        ),
                        reviewed_at=None,
                        withdrawn_at=None,
                        cvss_score=None,
                        epss_score=None,
                        epss_percentile=None,
                        normalizer_version="1.0.0",
                        normalized_at=datetime(
                            2026,
                            8,
                            2,
                            12,
                            0,
                            tzinfo=UTC,
                        ),
                    ),
                    GitHubAdvisoryVulnerabilityModel(
                        id=normalized_ids[1],
                        raw_payload_id=(
                            raw_payload_ids[1]
                        ),
                        ghsa_id=active_storage_ghsa,
                        cve_id=cve_id,
                        advisory_type="reviewed",
                        severity="HIGH",
                        summary="Second snapshot",
                        description=None,
                        published_at=datetime(
                            2026,
                            8,
                            1,
                            10,
                            0,
                            tzinfo=UTC,
                        ),
                        updated_at=datetime(
                            2026,
                            8,
                            3,
                            11,
                            0,
                            tzinfo=UTC,
                        ),
                        reviewed_at=None,
                        withdrawn_at=None,
                        cvss_score=None,
                        epss_score=None,
                        epss_percentile=None,
                        normalizer_version="1.0.0",
                        normalized_at=datetime(
                            2026,
                            8,
                            3,
                            12,
                            0,
                            tzinfo=UTC,
                        ),
                    ),
                    GitHubAdvisoryVulnerabilityModel(
                        id=normalized_ids[2],
                        raw_payload_id=(
                            raw_payload_ids[2]
                        ),
                        ghsa_id=withdrawn_storage_ghsa,
                        cve_id=None,
                        advisory_type="reviewed",
                        severity="LOW",
                        summary="Withdrawn snapshot",
                        description=None,
                        published_at=datetime(
                            2026,
                            8,
                            1,
                            10,
                            0,
                            tzinfo=UTC,
                        ),
                        updated_at=datetime(
                            2026,
                            8,
                            3,
                            11,
                            0,
                            tzinfo=UTC,
                        ),
                        reviewed_at=None,
                        withdrawn_at=datetime(
                            2026,
                            8,
                            4,
                            10,
                            0,
                            tzinfo=UTC,
                        ),
                        cvss_score=None,
                        epss_score=None,
                        epss_percentile=None,
                        normalizer_version="1.0.0",
                        normalized_at=datetime(
                            2026,
                            8,
                            4,
                            12,
                            0,
                            tzinfo=UTC,
                        ),
                    ),
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
                GitHubAdvisoryCanonicalCorrelationBatchService(
                    source=(
                        SqlAlchemyGitHubAdvisoryCanonicalSource(
                            session=session,
                        )
                    ),
                    builder=(
                        GitHubAdvisoryCanonicalObservationBuilder()
                    ),
                    correlation_service=(
                        correlation_service
                    ),
                )
            )

            first_batch = (
                batch_service.process_batch(
                    after_cursor=initial_cursor,
                    limit=1,
                )
            )

            assert first_batch.records_read == 1

            assert first_batch.next_cursor == (
                GitHubAdvisoryCanonicalCursor(
                    ghsa_id=active_storage_ghsa,
                    normalized_record_id=(
                        normalized_ids[0]
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
                == 1
            )

            assert (
                first_batch
                .correlation
                .created
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
                == "provisional"
            )

            assert [
                identifier.key
                for identifier
                in first_aggregate.identifiers
            ] == [
                (
                    "GHSA",
                    active_canonical_ghsa,
                )
            ]

            second_batch = (
                batch_service.process_batch(
                    after_cursor=(
                        first_batch.next_cursor
                    ),
                    limit=2,
                )
            )

            # Le troisième enregistrement est retiré
            # et doit être filtré directement en SQL.
            assert second_batch.records_read == 1

            assert second_batch.next_cursor == (
                GitHubAdvisoryCanonicalCursor(
                    ghsa_id=active_storage_ghsa,
                    normalized_record_id=(
                        normalized_ids[1]
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
                == 0
            )

            assert (
                second_batch
                .correlation
                .updated
                == 1
            )

            second_aggregate = (
                second_batch
                .correlation
                .aggregates[0]
            )

            canonical_ids.add(
                second_aggregate.id
            )

            assert (
                second_aggregate.id
                == first_aggregate.id
            )

            assert (
                second_aggregate
                .primary_identifier
                .key
                == (
                    "CVE",
                    cve_id,
                )
            )

            assert {
                identifier.key
                for identifier
                in second_aggregate.identifiers
            } == {
                (
                    "CVE",
                    cve_id,
                ),
                (
                    "GHSA",
                    active_canonical_ghsa,
                ),
            }

            assert len(
                second_aggregate.evidences
            ) == 1

            evidence = (
                second_aggregate.evidences[0]
            )

            assert evidence.key == (
                "github_advisory",
                active_canonical_ghsa,
            )

            assert (
                evidence.observed_at
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
                evidence.last_observed_at
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
                evidence.source_modified_at
                == datetime(
                    2026,
                    8,
                    3,
                    11,
                    0,
                    tzinfo=UTC,
                )
            )

            assert (
                evidence.normalized_record_id
                == str(
                    normalized_ids[1]
                )
            )

            replay = (
                batch_service.process_batch(
                    after_cursor=initial_cursor,
                    limit=1,
                )
            )

            assert replay.correlation.created == 0
            assert replay.correlation.updated == 1
            assert replay.correlation.persisted == 1

        with ingestion_session_factory() as session:
            identifiers = (
                session.execute(
                    select(
                        CanonicalVulnerabilityIdentifierModel
                    )
                    .where(
                        CanonicalVulnerabilityIdentifierModel
                        .value
                        .in_(
                            [
                                active_canonical_ghsa,
                                cve_id,
                                withdrawn_canonical_ghsa,
                            ]
                        )
                    )
                )
                .scalars()
                .all()
            )

            assert {
                identifier.value
                for identifier in identifiers
            } == {
                active_canonical_ghsa,
                cve_id,
            }

            evidences = (
                session.execute(
                    select(
                        CanonicalVulnerabilityEvidenceModel
                    )
                    .where(
                        CanonicalVulnerabilityEvidenceModel
                        .source
                        == "github_advisory"
                    )
                    .where(
                        CanonicalVulnerabilityEvidenceModel
                        .source_record_key
                        .in_(
                            [
                                active_canonical_ghsa,
                                withdrawn_canonical_ghsa,
                            ]
                        )
                    )
                )
                .scalars()
                .all()
            )

            assert len(evidences) == 1

            assert (
                evidences[0].source_record_key
                == active_canonical_ghsa
            )

            assert (
                evidences[0].evidence_type
                == "github_security_advisory"
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

            assert len(vulnerabilities) == 1

            assert (
                vulnerabilities[0].status
                == "provisional"
            )

    finally:
        with owner_session_factory() as session:
            session.execute(
                text(
                    "SET ROLE threat_intel_owner"
                )
            )

            discovered_ids = set(
                session.execute(
                    select(
                        CanonicalVulnerabilityIdentifierModel
                        .vulnerability_id
                    )
                    .where(
                        CanonicalVulnerabilityIdentifierModel
                        .value
                        .in_(
                            [
                                active_canonical_ghsa,
                                cve_id,
                                withdrawn_canonical_ghsa,
                            ]
                        )
                    )
                )
                .scalars()
                .all()
            )

            cleanup_ids = (
                canonical_ids
                | discovered_ids
            )

            if cleanup_ids:
                session.execute(
                    delete(
                        CanonicalVulnerabilityModel
                    ).where(
                        CanonicalVulnerabilityModel
                        .id
                        .in_(cleanup_ids)
                    )
                )

            session.execute(
                delete(
                    GitHubAdvisoryVulnerabilityModel
                ).where(
                    GitHubAdvisoryVulnerabilityModel
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