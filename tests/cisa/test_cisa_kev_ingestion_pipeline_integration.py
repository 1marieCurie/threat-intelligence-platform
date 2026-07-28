from __future__ import annotations

import os
from typing import Any
from uuid import UUID, uuid4

import pytest
import requests
from dotenv import load_dotenv
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

from application.services.ingestion_service import (
    IngestionService,
)
from infrastructure.adapters.inbound.raw_ingestion_job import (
    RawIngestionJob,
)
from infrastructure.adapters.outbound.cisa_connector import (
    CISAConnector,
)
from infrastructure.adapters.outbound.cisa.cisa_kev_ingestion_connector import (
    CisaKevIngestionConnector,
)
from infrastructure.persistence.models.ops import (
    IngestionRunModel,
    SourceModel,
    SyncStateModel,
)
from infrastructure.persistence.models.raw import (
    SourcePayloadModel,
)
from infrastructure.persistence.sqlalchemy import (
    SqlAlchemyUnitOfWork,
    create_ingestion_engine,
    create_session_factory,
)
from infrastructure.security.sha256_payload_hasher import (
    Sha256PayloadHasher,
)


load_dotenv()


pytestmark = pytest.mark.integration


class FakeResponse(requests.Response):
    def __init__(
        self,
        *,
        payload: Any,
        status_code: int = 200,
    ) -> None:
        super().__init__()

        self._payload = payload
        self.status_code = status_code

    def json(
        self,
        **kwargs: Any,
    ) -> Any:
        del kwargs

        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(
                f"HTTP error {self.status_code}",
                response=self,
            )


class FakeSession(requests.Session):
    def __init__(
        self,
        *,
        responses: list[requests.Response],
    ) -> None:
        super().__init__()

        self._responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def get(
        self,
        url: str,
        **kwargs: Any,
    ) -> requests.Response:
        self.calls.append(
            {
                "url": url,
                "timeout": kwargs.get("timeout"),
            }
        )

        if not self._responses:
            raise AssertionError(
                "FakeSession has no configured response."
            )

        return self._responses.pop(0)


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


def _create_source(
    *,
    owner_session_factory: sessionmaker[Session],
    source_id: UUID,
    source_code: str,
) -> None:
    with owner_session_factory() as session:
        session.execute(
            text("SET ROLE threat_intel_owner")
        )

        session.add(
            SourceModel(
                id=source_id,
                code=source_code,
                name=(
                    "CISA KEV pipeline integration test"
                ),
                base_url=CISAConnector.KEV_URL,
                enabled=True,
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
            text("SET ROLE threat_intel_owner")
        )

        run_ids = (
            select(IngestionRunModel.id)
            .where(
                IngestionRunModel.source_id
                == source_id
            )
        )

        session.execute(
            delete(SourcePayloadModel).where(
                SourcePayloadModel
                .ingestion_run_id
                .in_(run_ids)
            )
        )

        session.execute(
            delete(SyncStateModel).where(
                SyncStateModel.source_id
                == source_id
            )
        )

        session.execute(
            delete(IngestionRunModel).where(
                IngestionRunModel.source_id
                == source_id
            )
        )

        session.execute(
            delete(SourceModel).where(
                SourceModel.id == source_id
            )
        )

        session.commit()


def _build_catalog() -> dict[str, Any]:
    return {
        "title": (
            "CISA Known Exploited "
            "Vulnerabilities Catalog"
        ),
        "catalogVersion": "2026.07.28",
        "dateReleased": (
            "2026-07-28T12:00:00.0000Z"
        ),
        "count": 2,
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-0001",
                "vendorProject": "Vendor A",
                "product": "Product A",
                "vulnerabilityName": (
                    "Integration vulnerability A"
                ),
                "dateAdded": "2026-07-27",
                "shortDescription": (
                    "Integration test record A"
                ),
                "requiredAction": (
                    "Apply vendor mitigations."
                ),
                "dueDate": "2026-08-15",
                "knownRansomwareCampaignUse": (
                    "Unknown"
                ),
            },
            {
                "cveID": "CVE-2026-0002",
                "vendorProject": "Vendor B",
                "product": "Product B",
                "vulnerabilityName": (
                    "Integration vulnerability B"
                ),
                "dateAdded": "2026-07-28",
                "shortDescription": (
                    "Integration test record B"
                ),
                "requiredAction": (
                    "Apply vendor updates."
                ),
                "dueDate": "2026-08-16",
                "knownRansomwareCampaignUse": (
                    "Known"
                ),
            },
        ],
    }


def test_cisa_pipeline_persists_and_deduplicates() -> None:
    source_id = uuid4()
    source_code = (
        f"CISA_PIPE_{uuid4().hex[:20]}"
    )

    catalog = _build_catalog()

    fake_http_session = FakeSession(
        responses=[
            FakeResponse(
                payload=catalog,
            ),
            FakeResponse(
                payload=catalog,
            ),
        ]
    )

    source_connector = CISAConnector(
        session=fake_http_session,
        timeout=10,
    )

    ingestion_connector = (
        CisaKevIngestionConnector(
            connector=source_connector,
        )
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

    _create_source(
        owner_session_factory=owner_session_factory,
        source_id=source_id,
        source_code=source_code,
    )

    try:
        service = IngestionService(
            unit_of_work=SqlAlchemyUnitOfWork(
                session_factory=(
                    ingestion_session_factory
                ),
            ),
            connector=ingestion_connector,
            payload_hasher=Sha256PayloadHasher(),
        )

        job = RawIngestionJob(
            ingestion_service=service,
            source_id=source_id,
            source_code=source_code,
        )

        first_result = job.run()
        second_result = job.run()

        assert first_result.status == "completed"
        assert first_result.records_received == 2
        assert first_result.records_persisted == 2
        assert first_result.records_skipped == 0

        assert second_result.status == "completed"
        assert second_result.records_received == 2
        assert second_result.records_persisted == 0
        assert second_result.records_skipped == 2

        assert len(fake_http_session.calls) == 2

        assert all(
            call["url"] == CISAConnector.KEV_URL
            for call in fake_http_session.calls
        )

        assert all(
            call["timeout"] == 10.0
            for call in fake_http_session.calls
        )

        with ingestion_session_factory() as session:
            payloads = list(
                session.execute(
                    select(SourcePayloadModel)
                    .where(
                        SourcePayloadModel.source_id
                        == source_id
                    )
                    .order_by(
                        SourcePayloadModel
                        .external_record_id
                        .asc()
                    )
                )
                .scalars()
                .all()
            )

            runs = list(
                session.execute(
                    select(IngestionRunModel)
                    .where(
                        IngestionRunModel.source_id
                        == source_id
                    )
                    .order_by(
                        IngestionRunModel
                        .started_at
                        .asc()
                    )
                )
                .scalars()
                .all()
            )

            sync_state = session.get(
                SyncStateModel,
                source_id,
            )

            assert len(payloads) == 2
            assert len(runs) == 2

            assert [
                payload.external_record_id
                for payload in payloads
            ] == [
                "CVE-2026-0001",
                "CVE-2026-0002",
            ]

            assert all(
                payload.request_url
                == CISAConnector.KEV_URL
                for payload in payloads
            )

            assert all(
                payload.http_status == 200
                for payload in payloads
            )

            assert all(
                payload.retrieved_at is not None
                for payload in payloads
            )

            assert all(
                payload.processing_status
                == "pending"
                for payload in payloads
            )

            assert all(
                len(payload.payload_hash) == 64
                for payload in payloads
            )

            assert all(
                run.status == "completed"
                for run in runs
            )

            assert [
                run.records_succeeded
                for run in runs
            ] == [
                2,
                0,
            ]

            assert all(
                run.records_failed == 0
                for run in runs
            )

            assert sync_state is not None
            assert sync_state.cursor is None

            assert (
                sync_state.metadata_["source"]
                == "cisa_kev"
            )

            assert (
                sync_state.metadata_[
                    "catalog_version"
                ]
                == "2026.07.28"
            )

            assert (
                sync_state.metadata_[
                    "declared_count"
                ]
                == 2
            )

            assert (
                sync_state.metadata_[
                    "records_count"
                ]
                == 2
            )

            assert (
                sync_state.metadata_[
                    "pagination_complete"
                ]
                is True
            )
            assert runs[0].connector_version == "1.0.0"
            assert runs[0].metadata_["source"] == "cisa_kev"
            assert runs[0].metadata_["catalog_version"] == "2026.07.28"
            assert runs[0].metadata_["declared_count"] == 2
            assert runs[0].metadata_["records_count"] == 2

            assert runs[1].connector_version == "1.0.0"
            assert runs[1].metadata_["source"] == "cisa_kev"

    finally:
        _delete_test_data(
            owner_session_factory=(
                owner_session_factory
            ),
            source_id=source_id,
        )