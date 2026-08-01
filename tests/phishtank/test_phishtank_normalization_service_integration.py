from __future__ import annotations

import os
from typing import Any
from uuid import UUID, uuid4

from dotenv import load_dotenv

load_dotenv()

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

from application.ports.outbound.ingestion_run_payload_repository import (
    IngestionRunPayloadLink,
)
from application.ports.outbound.raw_payload_repository import (
    RawPayloadData,
)
from application.services.phishtank_normalization_service import (
    PhishTankNormalizationService,
)
from application.services.phishtank_normalizer import (
    PhishTankNormalizer,
)
from infrastructure.persistence.models.normalized_phishtank import (
    PhishTankPhishingModel,
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


class _FailingMarkProcessedRepository:
    """
    Décorateur de test simulant l'échec du passage à processed.

    Toutes les autres opérations sont déléguées au vrai
    repository PostgreSQL.
    """

    def __init__(
        self,
        repository: object,
    ) -> None:
        self._repository = repository

    def mark_processed(
        self,
        *,
        payload_id: UUID,
    ) -> bool:
        del payload_id
        return False

    def __getattr__(
        self,
        name: str,
    ) -> Any:
        return getattr(
            self._repository,
            name,
        )


class _FailingMarkProcessedUnitOfWork(
    SqlAlchemyUnitOfWork
):
    def __enter__(
        self,
    ) -> "_FailingMarkProcessedUnitOfWork":
        super().__enter__()

        self.raw_payloads = (
            _FailingMarkProcessedRepository(
                self.raw_payloads
            )
        )  # type: ignore[assignment]

        return self


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


def _create_source_and_completed_run(
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
                    "PhishTank normalization "
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
    phish_id: int,
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
                    external_record_id=str(
                        phish_id
                    ),
                    payload=payload,
                    payload_hash=(
                        uuid4().hex * 2
                    ),
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
                        raw_payload_id=(
                            payload_id
                        ),
                    ),
                )
            )
        )

        if (
            link_result.unique_count != 1
            or link_result.inserted_count != 1
        ):
            raise RuntimeError(
                "Unable to create the "
                "run/payload observation"
            )

        unit_of_work.commit()

    return payload_id


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

        session.execute(
            delete(
                PhishTankPhishingModel
            ).where(
                PhishTankPhishingModel
                .raw_payload_id
                .in_(payload_ids)
            )
        )

        # La suppression des payloads supprime aussi
        # les associations ingestion_run_payload
        # grâce au ON DELETE CASCADE.
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


def test_process_pending_persists_normalized_phishing(
) -> None:
    source_id = uuid4()
    ingestion_run_id = uuid4()

    source_code = (
        f"TEST_PHISHTANK_NORM_"
        f"{uuid4().hex[:16]}"
    )

    phish_id = (
        uuid4().int
        % 9_000_000_000
        + 1
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

    _create_source_and_completed_run(
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
            phish_id=phish_id,
            payload={
                "phish_id": phish_id,
                "url": (
                    "https://login.example.invalid/"
                    "account/verify"
                ),
                "phish_detail_url": (
                    "https://www.phishtank.com/"
                    "phish_detail.php?"
                    f"phish_id={phish_id}"
                ),
                "submission_time": (
                    "2026-07-13T11:03:01Z"
                ),
                "verification_time": (
                    "2026-07-13T11:52:26Z"
                ),
                "verified": "yes",
                "online": "yes",
                "target": "Other",
                "details": [
                    {
                        "ip_address": (
                            "192.0.2.10"
                        ),
                        "cidr_block": (
                            "192.0.2.0/24"
                        ),
                        "announcing_network": (
                            "64500"
                        ),
                        "rir": "ARIN",
                        "country": "MA",
                        "detail_time": (
                            "2026-07-13T11:12:10Z"
                        ),
                    },
                ],
            },
        )

        service = (
            PhishTankNormalizationService(
                unit_of_work=(
                    SqlAlchemyUnitOfWork(
                        session_factory=(
                            ingestion_session_factory
                        ),
                    )
                ),
                normalizer=(
                    PhishTankNormalizer()
                ),
            )
        )

        result = service.process_pending(
            source_id=source_id,
            limit=10,
        )

        assert result.claimed == 1
        assert result.normalized == 1
        assert (
            result.already_normalized
            == 0
        )
        assert result.failed == 0
        assert result.requeued == 0
        assert result.stale_failed == 0

        with ingestion_session_factory() as session:
            raw_payload = session.get(
                SourcePayloadModel,
                payload_id,
            )

            normalized = (
                session.execute(
                    select(
                        PhishTankPhishingModel
                    ).where(
                        PhishTankPhishingModel
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

            assert normalized is not None
            assert normalized.phish_id == phish_id

            assert normalized.hostname == (
                "login.example.invalid"
            )

            assert normalized.verified is True
            assert normalized.online is True
            assert normalized.target == "Other"

            assert (
                normalized.normalizer_version
                == "1.0.1"
            )

            assert normalized.network_details == [
                {
                    "ip_address": "192.0.2.10",
                    "cidr_block": "192.0.2.0/24",
                    "announcing_network": "64500",
                    "rir": "arin",
                    "country": "MA",
                    "detail_time": (
                        "2026-07-13T11:12:10+00:00"
                    ),
                }
            ]

        second_result = service.process_pending(
            source_id=source_id,
            limit=10,
        )

        assert second_result.claimed == 0
        assert second_result.normalized == 0
        assert second_result.failed == 0

    finally:
        _delete_test_data(
            owner_session_factory=(
                owner_session_factory
            ),
            source_id=source_id,
        )

        ingestion_engine.dispose()


def test_invalid_payload_is_failed_without_url_leak(
) -> None:
    source_id = uuid4()
    ingestion_run_id = uuid4()

    source_code = (
        f"TEST_PHISHTANK_FAILURE_"
        f"{uuid4().hex[:14]}"
    )

    phish_id = (
        uuid4().int
        % 9_000_000_000
        + 1
    )

    sensitive_url = (
        "ftp://user:super-secret@"
        "example.invalid/file"
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

    _create_source_and_completed_run(
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
            phish_id=phish_id,
            payload={
                "phish_id": phish_id,
                "url": sensitive_url,
            },
        )

        service = (
            PhishTankNormalizationService(
                unit_of_work=(
                    SqlAlchemyUnitOfWork(
                        session_factory=(
                            ingestion_session_factory
                        ),
                    )
                ),
                normalizer=(
                    PhishTankNormalizer()
                ),
            )
        )

        result = service.process_pending(
            source_id=source_id,
            limit=10,
        )

        assert result.claimed == 1
        assert result.normalized == 0
        assert result.failed == 1

        with ingestion_session_factory() as session:
            raw_payload = session.get(
                SourcePayloadModel,
                payload_id,
            )

            normalized = (
                session.execute(
                    select(
                        PhishTankPhishingModel
                    ).where(
                        PhishTankPhishingModel
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
                raw_payload.processing_attempts
                == 1
            )

            assert (
                raw_payload.error_message
                is not None
            )

            assert (
                sensitive_url
                not in raw_payload.error_message
            )

            assert (
                "super-secret"
                not in raw_payload.error_message
            )

            assert (
                "url must use http or https"
                in raw_payload.error_message
            )

            assert normalized is None

    finally:
        _delete_test_data(
            owner_session_factory=(
                owner_session_factory
            ),
            source_id=source_id,
        )

        ingestion_engine.dispose()


def test_normalized_insert_is_rolled_back_when_status_update_fails(
) -> None:
    source_id = uuid4()
    ingestion_run_id = uuid4()

    source_code = (
        f"TEST_PHISHTANK_ROLLBACK_"
        f"{uuid4().hex[:13]}"
    )

    phish_id = (
        uuid4().int
        % 9_000_000_000
        + 1
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

    _create_source_and_completed_run(
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
            phish_id=phish_id,
            payload={
                "phish_id": phish_id,
                "url": (
                    "https://rollback."
                    "example.invalid/login"
                ),
                "verified": "yes",
                "online": "yes",
            },
        )

        service = (
            PhishTankNormalizationService(
                unit_of_work=(
                    _FailingMarkProcessedUnitOfWork(
                        session_factory=(
                            ingestion_session_factory
                        ),
                    )
                ),
                normalizer=(
                    PhishTankNormalizer()
                ),
            )
        )

        result = service.process_pending(
            source_id=source_id,
            limit=10,
        )

        assert result.claimed == 1
        assert result.normalized == 0
        assert result.failed == 1

        with ingestion_session_factory() as session:
            raw_payload = session.get(
                SourcePayloadModel,
                payload_id,
            )

            normalized = (
                session.execute(
                    select(
                        PhishTankPhishingModel
                    ).where(
                        PhishTankPhishingModel
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
                raw_payload.error_message
                == (
                    "RuntimeError: unexpected "
                    "normalization failure"
                )
            )

            # L'insertion normalisée et le passage à
            # processed appartiennent à la même transaction.
            assert normalized is None

    finally:
        _delete_test_data(
            owner_session_factory=(
                owner_session_factory
            ),
            source_id=source_id,
        )

        ingestion_engine.dispose()