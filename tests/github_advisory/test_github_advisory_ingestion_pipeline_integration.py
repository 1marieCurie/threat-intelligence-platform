from __future__ import annotations

import os
from typing import Any
from uuid import UUID, uuid4

import pytest
import requests
from sqlalchemy import create_engine, delete, func, select, text
from sqlalchemy.orm import Session, sessionmaker

from application.services.ingestion_service import (
    IngestionService,
)
from infrastructure.adapters.outbound.github.github_advisory_ingestion_connector import (
    GitHubAdvisoryIngestionConnector,
)
from infrastructure.adapters.outbound.github_advisory_connector import (
    GitHubAdvisoryConnector,
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


pytestmark = pytest.mark.integration


class FakeResponse(requests.Response):
    def __init__(
        self,
        *,
        payload: Any,
        links: dict[str, Any] | None = None,
        status_code: int = 200,
    ) -> None:
        super().__init__()

        self._payload = payload
        self._fake_links = links or {}
        self.status_code = status_code

    def json(self, **kwargs: Any) -> Any:
        return self._payload

    @property
    def links(self) -> dict[str, Any]:
        return self._fake_links

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(
                f"HTTP error {self.status_code}",
                response=self,
            )


class FakeSession(requests.Session):
    def __init__(
        self,
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
                "headers": kwargs.get("headers"),
                "params": kwargs.get("params"),
                "timeout": kwargs.get("timeout"),
            }
        )

        if not self._responses:
            raise AssertionError(
                "FakeSession has no configured response."
            )

        return self._responses.pop(0)


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
                name="GitHub ingestion integration test",
                base_url="https://api.github.com/advisories",
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

        run_ids = select(
            IngestionRunModel.id
        ).where(
            IngestionRunModel.source_id == source_id
        )

        session.execute(
            delete(SourcePayloadModel).where(
                SourcePayloadModel.ingestion_run_id.in_(
                    run_ids
                )
            )
        )

        session.execute(
            delete(SyncStateModel).where(
                SyncStateModel.source_id == source_id
            )
        )

        session.execute(
            delete(IngestionRunModel).where(
                IngestionRunModel.source_id == source_id
            )
        )

        session.execute(
            delete(SourceModel).where(
                SourceModel.id == source_id
            )
        )

        session.commit()


def _build_advisory() -> dict[str, Any]:
    return {
        "ghsa_id": "GHSA-1234-5678-9012",
        "cve_id": "CVE-2026-0001",
        "html_url": (
            "https://github.com/advisories/"
            "GHSA-1234-5678-9012"
        ),
        "summary": "Integration test advisory",
        "severity": "high",
        "updated_at": "2026-07-24T10:00:00Z",
    }


def test_github_ingestion_pipeline_persists_and_deduplicates() -> None:
    source_id = uuid4()
    source_code = f"GH_PIPE_{uuid4().hex[:20]}"

    advisory = _build_advisory()

    first_response = FakeResponse(
        payload=[advisory],
        links={
            "next": {
                "url": (
                    "https://api.github.com/advisories"
                    "?type=reviewed"
                    "&sort=updated"
                    "&direction=asc"
                    "&per_page=100"
                    "&after=cursor-page-2"
                ),
            },
        },
    )

    second_response = FakeResponse(
        payload=[advisory],
        links={
            "next": {
                "url": (
                    "https://api.github.com/advisories"
                    "?type=reviewed"
                    "&sort=updated"
                    "&direction=asc"
                    "&per_page=100"
                    "&after=cursor-page-3"
                ),
            },
        },
    )

    fake_http_session = FakeSession(
        responses=[
            first_response,
            second_response,
        ]
    )

    github_connector = GitHubAdvisoryConnector(
        session=fake_http_session,
    )

    ingestion_connector = (
        GitHubAdvisoryIngestionConnector(
            connector=github_connector,
            per_page=100,
        )
    )

    owner_session_factory = (
        _create_owner_session_factory()
    )

    ingestion_engine = create_ingestion_engine()
    ingestion_session_factory = create_session_factory(
        ingestion_engine
    )

    _create_source(
        owner_session_factory=owner_session_factory,
        source_id=source_id,
        source_code=source_code,
    )

    try:
        service = IngestionService(
            unit_of_work=SqlAlchemyUnitOfWork(
                session_factory=ingestion_session_factory,
            ),
            connector=ingestion_connector,
            payload_hasher=Sha256PayloadHasher(),
        )

        first_result = service.ingest(
            source_id=source_id,
        )

        second_result = service.ingest(
            source_id=source_id,
        )

        assert first_result.status == "completed"
        assert first_result.records_received == 1
        assert first_result.records_persisted == 1
        assert first_result.records_skipped == 0

        assert second_result.status == "completed"
        assert second_result.records_received == 1
        assert second_result.records_persisted == 0
        assert second_result.records_skipped == 1

        assert len(fake_http_session.calls) == 2

        first_request = fake_http_session.calls[0]
        second_request = fake_http_session.calls[1]

        assert first_request["params"].get("after") is None
        assert (
            second_request["params"]["after"]
            == "cursor-page-2"
        )

        with ingestion_session_factory() as session:
            payload_count = session.scalar(
                select(
                    func.count(SourcePayloadModel.id)
                ).where(
                    SourcePayloadModel.source_id
                    == source_id
                )
            )

            runs = session.execute(
                select(IngestionRunModel)
                .where(
                    IngestionRunModel.source_id
                    == source_id
                )
                .order_by(
                    IngestionRunModel.started_at
                )
            ).scalars().all()

            sync_state = session.get(
                SyncStateModel,
                source_id,
            )

            payload = session.execute(
                select(SourcePayloadModel).where(
                    SourcePayloadModel.source_id
                    == source_id
                )
            ).scalar_one_or_none()

            assert payload_count == 1
            assert len(runs) == 2
            assert all(
                run.status == "completed"
                for run in runs
            )

            assert payload is not None
            assert (
                payload.external_record_id
                == "GHSA-1234-5678-9012"
            )
            assert payload.payload == advisory
            assert len(payload.payload_hash) == 64

            assert sync_state is not None
            assert sync_state.cursor == "cursor-page-3"
            assert sync_state.metadata_[
                "source"
            ] == "github_advisory"
            assert sync_state.metadata_[
                "records_count"
            ] == 1

    finally:
        _delete_test_data(
            owner_session_factory=owner_session_factory,
            source_id=source_id,
        )