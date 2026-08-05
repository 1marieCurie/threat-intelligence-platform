from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import (
    dataclass,
    field,
)
from datetime import (
    UTC,
    datetime,
    timedelta,
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
    func,
    select,
    text,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import (
    Session,
    sessionmaker,
)

from application.models.canonical_web_indicator_observation import (
    CanonicalWebIndicatorObservation,
)
from application.services.canonical_url_normalizer import (
    CanonicalURLNormalizer,
)
from application.services.canonical_web_indicator_correlation_service import (
    CanonicalWebCorrelationConflictError,
    CanonicalWebIndicatorCorrelationService,
)
from typing import Any, cast
from domain.web_indicator_observation import (
    WebIndicatorObservation,
)
from infrastructure.persistence.models.canonical_web import (
    CanonicalWebIndicatorModel,
    CanonicalWebIndicatorObservationModel,
)
from infrastructure.persistence.sqlalchemy import (
    SqlAlchemyUnitOfWork,
    create_ingestion_engine,
    create_session_factory,
)


pytestmark = pytest.mark.integration


NOW = datetime(
    2026,
    8,
    5,
    20,
    0,
    tzinfo=UTC,
)


@dataclass(
    slots=True,
)
class DatabaseContext:
    owner_session_factory: (
        sessionmaker[Session]
    )

    ingestion_session_factory: (
        sessionmaker[Session]
    )

    tracked_ids: set[UUID] = field(
        default_factory=set
    )

    def new_id(
        self,
    ) -> UUID:
        indicator_id = uuid4()

        self.tracked_ids.add(
            indicator_id
        )

        return indicator_id


def _owner_engine() -> Engine:
    database_url = os.environ.get(
        "MIGRATION_DATABASE_URL"
    )

    if not database_url:
        raise RuntimeError(
            "MIGRATION_DATABASE_URL "
            "is not defined"
        )

    return create_engine(
        database_url,
        pool_pre_ping=True,
    )


def _owner_session_factory(
    engine: Engine,
) -> sessionmaker[Session]:
    return sessionmaker(
        bind=engine,
        class_=Session,
        autoflush=False,
        expire_on_commit=False,
    )


def _cleanup(
    context: DatabaseContext,
) -> None:
    if not context.tracked_ids:
        return

    with (
        context.owner_session_factory()
        as session
    ):
        session.execute(
            text(
                "SET ROLE "
                "threat_intel_owner"
            )
        )

        session.execute(
            delete(
                CanonicalWebIndicatorModel
            ).where(
                CanonicalWebIndicatorModel
                .id
                .in_(
                    context.tracked_ids
                )
            )
        )

        session.commit()


@pytest.fixture
def database_context(
) -> Iterator[DatabaseContext]:
    owner_engine = _owner_engine()

    ingestion_engine: Engine | None = None

    context: DatabaseContext | None = None

    try:
        ingestion_engine = (
            create_ingestion_engine()
        )

        context = DatabaseContext(
            owner_session_factory=(
                _owner_session_factory(
                    owner_engine
                )
            ),
            ingestion_session_factory=(
                create_session_factory(
                    ingestion_engine
                )
            ),
        )

        yield context

    finally:
        try:
            if context is not None:
                _cleanup(
                    context
                )

        finally:
            if ingestion_engine is not None:
                ingestion_engine.dispose()

            owner_engine.dispose()


def _canonical_observation(
    *,
    source: str,
    source_record_key: str,
    url: str,
    normalized_record_id: UUID | None = None,
    observed_at: datetime = NOW,
    source_status: str | None = "online",
    is_active: bool | None = True,
    labels: tuple[str, ...] = (),
) -> CanonicalWebIndicatorObservation:
    identity = (
        CanonicalURLNormalizer()
        .normalize(
            url
        )
    )

    observation = WebIndicatorObservation(
        source=source,
        source_record_key=(
            source_record_key
        ),
        normalized_record_id=(
            normalized_record_id
            or uuid4()
        ),
        observed_at=observed_at,
        last_observed_at=observed_at,
        normalizer_version="1.0.0",
        source_status=source_status,
        is_active=is_active,
        labels=labels,
    )

    return CanonicalWebIndicatorObservation(
        identity=identity,
        observation=observation,
    )


def _service(
    context: DatabaseContext,
    *,
    clock_value: datetime = NOW,
) -> CanonicalWebIndicatorCorrelationService:
    return (
        CanonicalWebIndicatorCorrelationService(
            unit_of_work=cast(
                Any,
                SqlAlchemyUnitOfWork(
                    context
                    .ingestion_session_factory
                ),
            ),
            uuid_factory=context.new_id,
            clock=lambda: clock_value,
        )
    )


def test_persists_and_hydrates_two_sources(
    database_context: DatabaseContext,
) -> None:
    service = _service(
        database_context
    )

    phishtank_record_id = uuid4()
    urlhaus_record_id = uuid4()

    result = service.correlate(
        (
            _canonical_observation(
                source="phishtank",
                source_record_key=(
                    f"pt-{uuid4().hex}"
                ),
                url=(
                    "HTTPS://repository-test.invalid:"
                    "443/login"
                ),
                normalized_record_id=(
                    phishtank_record_id
                ),
                source_status="verified",
                labels=(
                    "phishing",
                ),
            ),
            _canonical_observation(
                source="urlhaus",
                source_record_key=(
                    f"uh-{uuid4().hex}"
                ),
                url=(
                    "https://repository-test.invalid/"
                    "login"
                ),
                normalized_record_id=(
                    urlhaus_record_id
                ),
                source_status="online",
                labels=(
                    "malware_distribution",
                ),
            ),
        )
    )

    assert result.created == 1
    assert result.persisted == 1

    indicator_id = (
        result.aggregates[0].id
    )

    with SqlAlchemyUnitOfWork(
        database_context
        .ingestion_session_factory
    ) as unit_of_work:
        persisted = (
            unit_of_work
            .canonical_web_indicators
            .find_by_id(
                indicator_id
            )
        )

    assert persisted is not None

    assert persisted.canonical_value == (
        "https://repository-test.invalid/login"
    )

    assert persisted.sources == (
        "phishtank",
        "urlhaus",
    )

    assert persisted.labels == (
        "phishing",
        "malware_distribution",
    )

    assert len(
        persisted.observations
    ) == 2


def test_reingestion_is_idempotent(
    database_context: DatabaseContext,
) -> None:
    source_record_key = (
        f"pt-{uuid4().hex}"
    )

    normalized_record_id = uuid4()

    observation = _canonical_observation(
        source="phishtank",
        source_record_key=(
            source_record_key
        ),
        url=(
            "https://idempotence-test.invalid/path"
        ),
        normalized_record_id=(
            normalized_record_id
        ),
        source_status="verified",
        labels=(
            "phishing",
        ),
    )

    first_service = _service(
        database_context
    )

    first_result = (
        first_service.correlate(
            (
                observation,
            )
        )
    )

    second_service = _service(
        database_context,
        clock_value=(
            NOW
            + timedelta(minutes=1)
        ),
    )

    second_result = (
        second_service.correlate(
            (
                observation,
            )
        )
    )

    assert first_result.created == 1
    assert second_result.created == 0
    assert second_result.updated == 1

    assert (
        second_result.aggregates[0].id
        == first_result.aggregates[0].id
    )

    with (
        database_context
        .owner_session_factory()
        as session
    ):
        session.execute(
            text(
                "SET ROLE "
                "threat_intel_owner"
            )
        )

        indicator_count = (
            session.scalar(
                select(
                    func.count()
                )
                .select_from(
                    CanonicalWebIndicatorModel
                )
                .where(
                    CanonicalWebIndicatorModel
                    .id
                    == first_result
                    .aggregates[0]
                    .id
                )
            )
        )

        observation_count = (
            session.scalar(
                select(
                    func.count()
                )
                .select_from(
                    CanonicalWebIndicatorObservationModel
                )
                .where(
                    CanonicalWebIndicatorObservationModel
                    .indicator_id
                    == first_result
                    .aggregates[0]
                    .id
                )
            )
        )

    assert indicator_count == 1
    assert observation_count == 1


def test_rejects_moving_source_observation(
    database_context: DatabaseContext,
) -> None:
    source_record_key = (
        f"uh-{uuid4().hex}"
    )

    service = _service(
        database_context
    )

    first_result = service.correlate(
        (
            _canonical_observation(
                source="urlhaus",
                source_record_key=(
                    source_record_key
                ),
                url=(
                    "https://conflict-test.invalid/a"
                ),
            ),
        )
    )

    with pytest.raises(
        CanonicalWebCorrelationConflictError,
        match="cannot be moved",
    ):
        service.correlate(
            (
                _canonical_observation(
                    source="urlhaus",
                    source_record_key=(
                        source_record_key
                    ),
                    url=(
                        "https://conflict-test.invalid/b"
                    ),
                ),
            )
        )

    with SqlAlchemyUnitOfWork(
        database_context
        .ingestion_session_factory
    ) as unit_of_work:
        persisted = (
            unit_of_work
            .canonical_web_indicators
            .find_by_id(
                first_result
                .aggregates[0]
                .id
            )
        )

    assert persisted is not None

    assert persisted.canonical_value == (
        "https://conflict-test.invalid/a"
    )

    assert len(
        persisted.observations
    ) == 1


def test_ingestion_role_has_no_delete_privilege(
    database_context: DatabaseContext,
) -> None:
    with (
        database_context
        .owner_session_factory()
        as session
    ):
        session.execute(
            text(
                "SET ROLE "
                "threat_intel_owner"
            )
        )

        privileges = session.execute(
            text(
                "SELECT "
                "has_table_privilege("
                "'threat_intel_ingestion_role', "
                "'canonical."
                "canonical_web_indicator', "
                "'SELECT'"
                "), "
                "has_table_privilege("
                "'threat_intel_ingestion_role', "
                "'canonical."
                "canonical_web_indicator', "
                "'INSERT'"
                "), "
                "has_table_privilege("
                "'threat_intel_ingestion_role', "
                "'canonical."
                "canonical_web_indicator', "
                "'UPDATE'"
                "), "
                "has_table_privilege("
                "'threat_intel_ingestion_role', "
                "'canonical."
                "canonical_web_indicator', "
                "'DELETE'"
                ")"
            )
        ).one()

    assert privileges == (
        True,
        True,
        True,
        False,
    )