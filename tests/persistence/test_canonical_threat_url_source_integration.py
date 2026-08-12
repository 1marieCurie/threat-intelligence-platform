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
)
from hashlib import sha256
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
    text,
)
from sqlalchemy.engine import Engine
from sqlalchemy.orm import (
    Session,
    sessionmaker,
)

from application.models.canonical_threat_url_candidate import (
    CanonicalThreatURLCursor,
)
from infrastructure.persistence.models.canonical_web import (
    CanonicalWebIndicatorModel,
    CanonicalWebIndicatorObservationModel,
)
from infrastructure.persistence.sqlalchemy import (
    create_ingestion_engine,
    create_session_factory,
)
from infrastructure.persistence.sqlalchemy.readers.canonical_threat_url_source import (
    SqlAlchemyCanonicalThreatURLSource,
)


pytestmark = pytest.mark.integration


TEST_CANONICALIZATION_VERSION = 999_999

OBSERVED_AT = datetime(
    2026,
    8,
    12,
    12,
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

    indicator_ids: set[UUID] = field(
        default_factory=set
    )


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
    if not context.indicator_ids:
        return

    with (
        context.owner_session_factory()
        as session
    ):
        session.execute(
            text(
                "SET ROLE threat_intel_owner"
            )
        )

        session.execute(
            delete(
                CanonicalWebIndicatorModel
            ).where(
                CanonicalWebIndicatorModel.id.in_(
                    context.indicator_ids
                )
            )
        )

        session.commit()


@pytest.fixture
def database_context(
) -> Iterator[DatabaseContext]:
    owner_engine = (
        _owner_engine()
    )

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


def _insert_indicator(
    *,
    context: DatabaseContext,
    session: Session,
    token: str,
    sources: tuple[str, ...],
) -> UUID:
    indicator_id = uuid4()

    canonical_value = (
        "https://"
        f"{token}.example.test/"
        "resource"
    )

    value_hash = sha256(
        canonical_value.encode(
            "utf-8"
        )
    ).hexdigest()

    hostname = (
        f"{token}.example.test"
    )

    indicator = CanonicalWebIndicatorModel(
        id=indicator_id,
        indicator_type="url",
        canonical_value=canonical_value,
        value_hash=value_hash,
        hostname=hostname,
        canonicalization_version=(
            TEST_CANONICALIZATION_VERSION
        ),
        created_at=OBSERVED_AT,
        updated_at=OBSERVED_AT,
    )

    session.add(
        indicator
    )

    for source in sources:
        session.add(
            CanonicalWebIndicatorObservationModel(
                id=uuid4(),
                indicator_id=indicator_id,
                source=source,
                source_record_key=(
                    f"{source}-{token}"
                ),
                normalized_record_id=(
                    uuid4()
                ),
                observed_at=OBSERVED_AT,
                last_observed_at=OBSERVED_AT,
                normalizer_version="integration-test",
                source_status="active",
                is_active=True,
                labels=[],
            )
        )

    context.indicator_ids.add(
        indicator_id
    )

    return indicator_id


def test_source_excludes_cross_source_ambiguity(
    database_context: DatabaseContext,
) -> None:
    run_id = uuid4().hex[:16]

    with (
        database_context
        .owner_session_factory()
        as session
    ):
        session.execute(
            text(
                "SET ROLE threat_intel_owner"
            )
        )

        phishing_id = _insert_indicator(
            context=database_context,
            session=session,
            token=f"phishing-{run_id}",
            sources=(
                "phishtank",
            ),
        )

        malware_id = _insert_indicator(
            context=database_context,
            session=session,
            token=f"malware-{run_id}",
            sources=(
                "urlhaus",
            ),
        )

        ambiguous_id = _insert_indicator(
            context=database_context,
            session=session,
            token=f"ambiguous-{run_id}",
            sources=(
                "phishtank",
                "urlhaus",
            ),
        )

        session.commit()

    starting_cursor = (
        CanonicalThreatURLCursor(
            canonicalization_version=(
                TEST_CANONICALIZATION_VERSION
                - 1
            ),
            value_hash=(
                "f" * 64
            ),
            indicator_id=UUID(
                int=0
            ),
        )
    )

    with (
        database_context
        .ingestion_session_factory()
        as session
    ):
        reader = (
            SqlAlchemyCanonicalThreatURLSource(
                session=session
            )
        )

        phishing = reader.read_batch(
            label_code="phishing",
            after_cursor=starting_cursor,
            limit=100,
        )

        malware = reader.read_batch(
            label_code="malware",
            after_cursor=starting_cursor,
            limit=100,
        )

    phishing_ids = {
        candidate
        .canonical_web_indicator_id
        for candidate in phishing
    }

    malware_ids = {
        candidate
        .canonical_web_indicator_id
        for candidate in malware
    }

    assert (
        phishing_id
        in phishing_ids
    )

    assert (
        malware_id
        not in phishing_ids
    )

    assert (
        malware_id
        in malware_ids
    )

    assert (
        phishing_id
        not in malware_ids
    )

    assert (
        ambiguous_id
        not in phishing_ids
    )

    assert (
        ambiguous_id
        not in malware_ids
    )


def test_candidate_repr_does_not_expose_url(
    database_context: DatabaseContext,
) -> None:
    run_id = uuid4().hex[:16]

    with (
        database_context
        .owner_session_factory()
        as session
    ):
        session.execute(
            text(
                "SET ROLE threat_intel_owner"
            )
        )

        indicator_id = _insert_indicator(
            context=database_context,
            session=session,
            token=f"privacy-{run_id}",
            sources=(
                "phishtank",
            ),
        )

        session.commit()

    starting_cursor = (
        CanonicalThreatURLCursor(
            canonicalization_version=(
                TEST_CANONICALIZATION_VERSION
                - 1
            ),
            value_hash=(
                "f" * 64
            ),
            indicator_id=UUID(
                int=0
            ),
        )
    )

    with (
        database_context
        .ingestion_session_factory()
        as session
    ):
        reader = (
            SqlAlchemyCanonicalThreatURLSource(
                session=session
            )
        )

        candidates = reader.read_batch(
            label_code="phishing",
            after_cursor=starting_cursor,
            limit=100,
        )

    candidate = next(
        item
        for item in candidates
        if (
            item
            .canonical_web_indicator_id
            == indicator_id
        )
    )

    representation = repr(
        candidate
    )

    assert (
        "https://"
        not in representation
    )

    assert (
        candidate.hostname
        not in representation
    )

    assert (
        candidate.value_hash
        not in representation
    )