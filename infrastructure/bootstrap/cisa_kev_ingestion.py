from __future__ import annotations

from uuid import UUID

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


CISA_KEV_SOURCE_CODE = "CISA_KEV"


def build_cisa_kev_ingestion_job(
    *,
    source_id: UUID,
) -> RawIngestionJob:
    """
    Assemble le pipeline brut CISA KEV.
    """

    if not isinstance(source_id, UUID):
        raise TypeError(
            "source_id must be a UUID"
        )

    source_connector = CISAConnector()

    ingestion_connector = (
        CisaKevIngestionConnector(
            connector=source_connector,
        )
    )

    engine = create_ingestion_engine()

    session_factory = create_session_factory(
        engine
    )

    unit_of_work = SqlAlchemyUnitOfWork(
        session_factory=session_factory,
    )

    ingestion_service = IngestionService(
        unit_of_work=unit_of_work,
        connector=ingestion_connector,
        payload_hasher=Sha256PayloadHasher(),
    )

    return RawIngestionJob(
        ingestion_service=ingestion_service,
        source_id=source_id,
        source_code=CISA_KEV_SOURCE_CODE,
    )