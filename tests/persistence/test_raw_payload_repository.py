from unittest.mock import Mock
from uuid import uuid4

from sqlalchemy.orm import Session

from application.ports.outbound.raw_payload_repository import (
    RawPayloadData,
)
from infrastructure.persistence.sqlalchemy.repositories.raw_payload_repository import (
    SqlAlchemyRawPayloadRepository,
)


def test_save_adds_payload_and_flushes_session() -> None:
    session = Mock(spec=Session)

    repository = SqlAlchemyRawPayloadRepository(
        session=session,
    )

    payload = RawPayloadData(
        source_id=uuid4(),
        ingestion_run_id=uuid4(),
        external_record_id="CVE-2026-0001",
        payload={
            "id": "CVE-2026-0001",
        },
        payload_hash="a" * 64,
        http_status=200,
    )

    payload_id = repository.save(payload)

    assert payload_id is not None
    session.add.assert_called_once()
    session.flush.assert_called_once_with()
    session.commit.assert_not_called()