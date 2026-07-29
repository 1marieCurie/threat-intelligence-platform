from __future__ import annotations

from dotenv import load_dotenv

load_dotenv()

import os
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

import pytest
from sqlalchemy import (
    create_engine,
    delete,
    select,
    text,
    update,
)
from sqlalchemy.orm import (
    Session,
    sessionmaker,
)

from application.ports.outbound.github_advisory_vulnerability_repository import (
    GitHubAdvisoryVulnerabilityData,
)
from application.ports.outbound.raw_payload_repository import (
    RawPayloadData,
)
from application.services.github_advisory_normalization_service import (
    GitHubAdvisoryNormalizationService,
)
from application.services.github_advisory_normalizer import (
    GitHubAdvisoryNormalizationError,
    GitHubAdvisoryNormalizer,
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


pytestmark = pytest.mark.integration


class SecretFailingGitHubAdvisoryNormalizer(
    GitHubAdvisoryNormalizer
):
    def normalize(
        self,
        *,
        raw_payload_id: UUID,
        payload: Mapping[str, Any],
    ) -> GitHubAdvisoryVulnerabilityData:
        del raw_payload_id
        del payload

        raise GitHubAdvisoryNormalizationError(
            "authorization: Bearer "
            "super-secret-github-token"
        )


def _create_owner_session_factory(
) -> sessionmaker[Session]:
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


def _build_ghsa_id() -> str:
    value = uuid4().hex

    return (
        "GHSA-"
        f"{value[:4]}-"
        f"{value[4:8]}-"
        f"{value[8:12]}"
    )


def _build_cve_id(
    *,
    year: int = 2099,
) -> str:
    identifier = (
        uuid4().int
        % 1_000_000_000
    )

    return (
        f"CVE-{year}-"
        f"{identifier:09d}"
    )


def _build_valid_payload(
    *,
    ghsa_id: str,
    cve_id: str,
    summary: str,
) -> dict[str, object]:
    return {
        "ghsa_id": ghsa_id,
        "cve_id": cve_id,
        "identifiers": [
            {
                "type": "GHSA",
                "value": ghsa_id,
            },
            {
                "type": "CVE",
                "value": cve_id,
            },
        ],
        "type": "reviewed",
        "severity": "high",
        "summary": summary,
        "description": (
            "GitHub Advisory normalization "
            "integration test."
        ),
        "published_at": (
            "2026-07-20T10:00:00Z"
        ),
        "updated_at": (
            "2026-07-29T12:00:00Z"
        ),
        "cvss_severities": {
            "cvss_v3": {
                "score": 8.8,
                "vector_string": (
                    "CVSS:3.1/AV:N/AC:L/"
                    "PR:N/UI:N/S:U/C:H/I:H/A:H"
                ),
            },
        },
        "epss": {
            "percentage": 0.42,
            "percentile": 0.91,
        },
        "vulnerabilities": [
            {
                "package": {
                    "ecosystem": "pip",
                    "name": (
                        "integration-package"
                    ),
                },
                "vulnerable_version_range": (
                    "< 2.0.0"
                ),
                "first_patched_version": {
                    "identifier": "2.0.0",
                },
                "vulnerable_functions": [
                    "package.execute",
                ],
                "source_code_location": {
                    "path": "src/package.py",
                },
            },
        ],
        "cwes": [
            {
                "cwe_id": "CWE-79",
                "name": (
                    "Improper Neutralization "
                    "of Input"
                ),
            },
        ],
        "references": [
            {
                "url": (
                    "https://example.com/"
                    "security/advisory"
                ),
            },
        ],
        "html_url": (
            "https://github.com/advisories/"
            f"{ghsa_id}"
        ),
    }


def _create_source_and_run(
    *,
    owner_session_factory: (
        sessionmaker[Session]
    ),
    ingestion_session_factory: (
        sessionmaker[Session]
    ),
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
                    "GitHub Advisory normalization "
                    "service integration test"
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
    ingestion_session_factory: (
        sessionmaker[Session]
    ),
    source_id: UUID,
    ingestion_run_id: UUID,
    external_record_id: str,
    payload: dict[str, object],
) -> UUID:
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
                    external_record_id=(
                        external_record_id
                    ),
                    payload=payload,
                    payload_hash=(
                        uuid4().hex * 2
                    ),
                    request_url=(
                        "https://api.github.com/"
                        "advisories/"
                        f"{external_record_id}"
                    ),
                    http_status=200,
                    processing_status="pending",
                )
            )
        )

        unit_of_work.commit()

    return payload_id


def _force_processing_lease(
    *,
    ingestion_session_factory: (
        sessionmaker[Session]
    ),
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

        assert (
            updated_payload_id
            == payload_id
        )

        session.commit()


def _reset_payload_to_pending(
    *,
    ingestion_session_factory: (
        sessionmaker[Session]
    ),
    payload_id: UUID,
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
                processing_status="pending",
                processing_started_at=None,
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

        assert (
            updated_payload_id
            == payload_id
        )

        session.commit()


def _delete_test_data(
    *,
    owner_session_factory: (
        sessionmaker[Session]
    ),
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

        session.execute(
            delete(
                GitHubAdvisoryVulnerabilityModel
            ).where(
                GitHubAdvisoryVulnerabilityModel
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


def test_process_pending_persists_and_repairs_idempotently(
) -> None:
    source_id = uuid4()
    ingestion_run_id = uuid4()

    source_code = (
        f"TEST_GHAD_NORMALIZE_"
        f"{uuid4().hex[:14]}"
    )

    ghsa_id = _build_ghsa_id()
    cve_id = _build_cve_id()

    owner_session_factory = (
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
            ingestion_run_id=(
                ingestion_run_id
            ),
            external_record_id=ghsa_id,
            payload=_build_valid_payload(
                ghsa_id=ghsa_id,
                cve_id=cve_id,
                summary=(
                    "GHAD integration advisory"
                ),
            ),
        )

        service = (
            GitHubAdvisoryNormalizationService(
                unit_of_work=(
                    SqlAlchemyUnitOfWork(
                        session_factory=(
                            ingestion_session_factory
                        ),
                    )
                ),
                normalizer=(
                    GitHubAdvisoryNormalizer()
                ),
            )
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
                        GitHubAdvisoryVulnerabilityModel
                    ).where(
                        GitHubAdvisoryVulnerabilityModel
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

            assert (
                raw_payload.error_message
                is None
            )

            assert vulnerability is not None

            assert (
                vulnerability.ghsa_id
                == ghsa_id
            )

            assert (
                vulnerability.cve_id
                == cve_id
            )

            assert (
                vulnerability.severity
                == "HIGH"
            )

            assert (
                vulnerability.cvss_score
                == pytest.approx(8.8)
            )

            assert (
                vulnerability.epss_score
                == pytest.approx(0.42)
            )

            assert (
                vulnerability.cwe_ids
                == ["CWE-79"]
            )

            assert (
                vulnerability.affected_packages[
                    0
                ]["package_name"]
                == "integration-package"
            )

            assert (
                vulnerability.normalizer_version
                == "1.0.0"
            )

        # Simulation d’un état incohérent :
        # la ligne normalisée existe, mais le payload
        # brut est de nouveau marqué pending.
        _reset_payload_to_pending(
            ingestion_session_factory=(
                ingestion_session_factory
            ),
            payload_id=payload_id,
        )

        repaired_result = (
            service.process_pending(
                source_id=source_id,
                limit=10,
            )
        )

        assert repaired_result.claimed == 1
        assert repaired_result.normalized == 0

        assert (
            repaired_result
            .already_normalized
            == 1
        )

        assert repaired_result.failed == 0

        with ingestion_session_factory() as session:
            raw_payload = session.get(
                SourcePayloadModel,
                payload_id,
            )

            normalized_rows = (
                session.execute(
                    select(
                        GitHubAdvisoryVulnerabilityModel
                    ).where(
                        GitHubAdvisoryVulnerabilityModel
                        .raw_payload_id
                        == payload_id
                    )
                )
                .scalars()
                .all()
            )

            assert raw_payload is not None

            assert (
                raw_payload.processing_status
                == "processed"
            )

            assert (
                raw_payload.processing_attempts
                == 2
            )

            # L’idempotence interdit une
            # deuxième ligne normalisée.
            assert len(normalized_rows) == 1

        empty_result = service.process_pending(
            source_id=source_id,
            limit=10,
        )

        assert empty_result.claimed == 0
        assert empty_result.normalized == 0

    finally:
        _delete_test_data(
            owner_session_factory=(
                owner_session_factory
            ),
            source_id=source_id,
        )

        ingestion_engine.dispose()


def test_failure_is_persisted_and_secret_is_redacted(
) -> None:
    source_id = uuid4()
    ingestion_run_id = uuid4()

    source_code = (
        f"TEST_GHAD_FAILURE_"
        f"{uuid4().hex[:16]}"
    )

    ghsa_id = _build_ghsa_id()
    cve_id = _build_cve_id()

    owner_session_factory = (
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
            ingestion_run_id=(
                ingestion_run_id
            ),
            external_record_id=ghsa_id,
            payload=_build_valid_payload(
                ghsa_id=ghsa_id,
                cve_id=cve_id,
                summary="Failure test",
            ),
        )

        service = (
            GitHubAdvisoryNormalizationService(
                unit_of_work=(
                    SqlAlchemyUnitOfWork(
                        session_factory=(
                            ingestion_session_factory
                        ),
                    )
                ),
                normalizer=(
                    SecretFailingGitHubAdvisoryNormalizer()
                ),
            )
        )

        result = service.process_pending(
            source_id=source_id,
            limit=10,
        )

        assert result.claimed == 1
        assert result.normalized == 0
        assert result.already_normalized == 0
        assert result.failed == 1

        with ingestion_session_factory() as session:
            raw_payload = session.get(
                SourcePayloadModel,
                payload_id,
            )

            vulnerability = (
                session.execute(
                    select(
                        GitHubAdvisoryVulnerabilityModel
                    ).where(
                        GitHubAdvisoryVulnerabilityModel
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

            assert (
                raw_payload.error_message
                is not None
            )

            assert (
                "super-secret-github-token"
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


def test_stale_processing_payloads_are_recovered(
) -> None:
    source_id = uuid4()
    ingestion_run_id = uuid4()

    source_code = (
        f"TEST_GHAD_RECOVERY_"
        f"{uuid4().hex[:15]}"
    )

    retry_ghsa_id = _build_ghsa_id()
    retry_cve_id = _build_cve_id()

    exhausted_ghsa_id = _build_ghsa_id()
    exhausted_cve_id = _build_cve_id(
        year=2098
    )

    owner_session_factory = (
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
            ingestion_run_id=(
                ingestion_run_id
            ),
            external_record_id=(
                retry_ghsa_id
            ),
            payload=_build_valid_payload(
                ghsa_id=retry_ghsa_id,
                cve_id=retry_cve_id,
                summary=(
                    "Recoverable GHAD payload"
                ),
            ),
        )

        exhausted_payload_id = (
            _save_pending_payload(
                ingestion_session_factory=(
                    ingestion_session_factory
                ),
                source_id=source_id,
                ingestion_run_id=(
                    ingestion_run_id
                ),
                external_record_id=(
                    exhausted_ghsa_id
                ),
                payload=_build_valid_payload(
                    ghsa_id=(
                        exhausted_ghsa_id
                    ),
                    cve_id=(
                        exhausted_cve_id
                    ),
                    summary=(
                        "Exhausted GHAD payload"
                    ),
                ),
            )
        )

        stale_started_at = (
            datetime.now(UTC)
            - timedelta(hours=1)
        )

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

        _force_processing_lease(
            ingestion_session_factory=(
                ingestion_session_factory
            ),
            payload_id=(
                exhausted_payload_id
            ),
            processing_started_at=(
                stale_started_at
            ),
            processing_attempts=3,
        )

        service = (
            GitHubAdvisoryNormalizationService(
                unit_of_work=(
                    SqlAlchemyUnitOfWork(
                        session_factory=(
                            ingestion_session_factory
                        ),
                    )
                ),
                normalizer=(
                    GitHubAdvisoryNormalizer()
                ),
                lease_timeout=timedelta(
                    minutes=15
                ),
                max_attempts=3,
            )
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
                        GitHubAdvisoryVulnerabilityModel
                    ).where(
                        GitHubAdvisoryVulnerabilityModel
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

            assert (
                retry_payload.processing_attempts
                == 2
            )

            assert (
                retry_payload.error_message
                is None
            )

            assert exhausted_payload is not None

            assert (
                exhausted_payload.processing_status
                == "failed"
            )

            assert (
                exhausted_payload
                .processing_started_at
                is None
            )

            assert (
                exhausted_payload
                .processing_attempts
                == 3
            )

            assert (
                exhausted_payload.error_message
                == (
                    "Processing lease expired "
                    "after maximum attempts"
                )
            )

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