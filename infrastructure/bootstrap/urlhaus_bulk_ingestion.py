from __future__ import annotations

import os
from pathlib import Path
from uuid import UUID

from dotenv import load_dotenv
from sqlalchemy.engine import Engine

from application.services.urlhaus_bulk_ingestion_service import (
    URLhausBulkIngestionService,
)
from infrastructure.adapters.outbound.urlhaus.urlhaus_database_dump_connector import (
    DEFAULT_DUMP_SCOPE,
    URLhausDatabaseDumpConnector,
    parse_urlhaus_dump_scope,
)
from infrastructure.persistence.sqlalchemy.engine import (
    create_ingestion_engine,
)
from infrastructure.persistence.sqlalchemy.session import (
    create_session_factory,
)
from infrastructure.persistence.sqlalchemy.unit_of_work import (
    SqlAlchemyUnitOfWork,
)
from infrastructure.security.sha256_payload_hasher import (
    Sha256PayloadHasher,
)


PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[2]
)

load_dotenv(
    dotenv_path=PROJECT_ROOT / ".env",
    override=False,
)


def build_urlhaus_bulk_ingestion(
    *,
    batch_size: int = 500,
    dump_scope: str = (
        DEFAULT_DUMP_SCOPE
    ),
) -> tuple[
    URLhausDatabaseDumpConnector,
    URLhausBulkIngestionService,
    UUID,
    Engine,
]:
    normalized_dump_scope = (
        parse_urlhaus_dump_scope(
            dump_scope
        )
    )

    auth_key = os.environ.get(
        "URLHAUS_AUTH_KEY"
    )

    if (
        normalized_dump_scope
        == "active_or_last_90_days"
    ):
        if (
            not isinstance(
                auth_key,
                str,
            )
            or not auth_key.strip()
        ):
            raise RuntimeError(
                "URLHAUS_AUTH_KEY is required "
                "for active_or_last_90_days"
            )

    source_id_value = os.environ.get(
        "URLHAUS_SOURCE_ID"
    )

    if (
        not isinstance(
            source_id_value,
            str,
        )
        or not source_id_value.strip()
    ):
        raise RuntimeError(
            "URLHAUS_SOURCE_ID is required"
        )

    try:
        source_id = UUID(
            source_id_value.strip()
        )

    except ValueError as error:
        raise RuntimeError(
            "URLHAUS_SOURCE_ID "
            "must be a valid UUID"
        ) from error

    engine = (
        create_ingestion_engine()
    )

    session_factory = (
        create_session_factory(
            engine
        )
    )

    connector = (
        URLhausDatabaseDumpConnector(
            auth_key=auth_key,
            dump_scope=(
                normalized_dump_scope
            ),
        )
    )

    service = (
        URLhausBulkIngestionService(
            unit_of_work=(
                SqlAlchemyUnitOfWork(
                    session_factory
                )
            ),
            payload_hasher=(
                Sha256PayloadHasher()
            ),
            batch_size=batch_size,
        )
    )

    return (
        connector,
        service,
        source_id,
        engine,
    )