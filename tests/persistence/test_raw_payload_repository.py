from datetime import UTC, datetime
from unittest.mock import Mock
from uuid import uuid4

import pytest
from sqlalchemy.orm import Session

from application.ports.outbound.raw_payload_repository import (
    RawPayloadData,
)
from infrastructure.persistence.models.raw import (
    SourcePayloadModel,
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

def test_claim_pending_marks_payloads_as_processing() -> None:
    session = Mock(spec=Session)

    repository = SqlAlchemyRawPayloadRepository(
        session=session,
    )

    payload_id = uuid4()
    source_id = uuid4()
    ingestion_run_id = uuid4()
    retrieved_at = datetime.now(UTC)

    model = SourcePayloadModel(
        id=payload_id,
        source_id=source_id,
        ingestion_run_id=ingestion_run_id,
        external_record_id="GHSA-aaaa-bbbb-cccc",
        retrieved_at=retrieved_at,
        payload={
            "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        },
        payload_hash="a" * 64,
        processing_status="pending",
        error_message="ancienne erreur",
    )

    execute_result = Mock()
    scalar_result = Mock()

    session.execute.return_value = execute_result
    execute_result.scalars.return_value = scalar_result
    scalar_result.all.return_value = [model]

    claimed_payloads = repository.claim_pending(
        source_id=source_id,
        limit=10,
    )

    assert len(claimed_payloads) == 1

    claimed_payload = claimed_payloads[0]

    assert claimed_payload.id == payload_id
    assert claimed_payload.source_id == source_id
    assert claimed_payload.processing_status == "processing"
    assert claimed_payload.error_message is None

    assert model.processing_status == "processing"
    assert model.error_message is None

    session.execute.assert_called_once()
    session.flush.assert_called_once_with()
    session.commit.assert_not_called()

def test_claim_pending_returns_empty_sequence() -> None:
    session = Mock(spec=Session)

    repository = SqlAlchemyRawPayloadRepository(
        session=session,
    )

    execute_result = Mock()
    scalar_result = Mock()

    session.execute.return_value = execute_result
    execute_result.scalars.return_value = scalar_result
    scalar_result.all.return_value = []

    claimed_payloads = repository.claim_pending(
        source_id=uuid4(),
        limit=10,
    )

    assert claimed_payloads == []
    session.flush.assert_called_once_with()
    session.commit.assert_not_called()
    
@pytest.mark.parametrize(
    ("invalid_limit", "expected_exception"),
    [
        (True, TypeError),
        ("10", TypeError),
        (0, ValueError),
        (-1, ValueError),
    ],
)
def test_claim_pending_rejects_invalid_limit(
    invalid_limit: object,
    expected_exception: type[Exception],
) -> None:
    session = Mock(spec=Session)

    repository = SqlAlchemyRawPayloadRepository(
        session=session,
    )

    with pytest.raises(expected_exception):
        repository.claim_pending(
            source_id=uuid4(),
            limit=invalid_limit,  # type: ignore[arg-type]
        )

    session.execute.assert_not_called()
    session.flush.assert_not_called()

def test_mark_processed_returns_true_when_payload_is_updated() -> None:
    session = Mock(spec=Session)

    repository = SqlAlchemyRawPayloadRepository(
        session=session,
    )

    payload_id = uuid4()

    execute_result = Mock()
    execute_result.scalar_one_or_none.return_value = payload_id
    session.execute.return_value = execute_result

    updated = repository.mark_processed(
        payload_id=payload_id,
    )

    assert updated is True
    session.execute.assert_called_once()
    session.commit.assert_not_called()
    
def test_mark_processed_returns_false_when_payload_is_not_updated() -> None:
    session = Mock(spec=Session)

    repository = SqlAlchemyRawPayloadRepository(
        session=session,
    )

    execute_result = Mock()
    execute_result.scalar_one_or_none.return_value = None
    session.execute.return_value = execute_result

    updated = repository.mark_processed(
        payload_id=uuid4(),
    )

    assert updated is False
    session.execute.assert_called_once()
    
def test_mark_failed_returns_true_when_payload_is_updated() -> None:
    session = Mock(spec=Session)

    repository = SqlAlchemyRawPayloadRepository(
        session=session,
    )

    payload_id = uuid4()

    execute_result = Mock()
    execute_result.scalar_one_or_none.return_value = payload_id
    session.execute.return_value = execute_result

    updated = repository.mark_failed(
        payload_id=payload_id,
        error_message="Normalization failed",
    )

    assert updated is True
    session.execute.assert_called_once()
    session.commit.assert_not_called()
    
@pytest.mark.parametrize(
    "invalid_error_message",
    [
        "",
        "   ",
    ],
)
def test_mark_failed_rejects_empty_error_message(
    invalid_error_message: str,
) -> None:
    session = Mock(spec=Session)

    repository = SqlAlchemyRawPayloadRepository(
        session=session,
    )

    with pytest.raises(ValueError):
        repository.mark_failed(
            payload_id=uuid4(),
            error_message=invalid_error_message,
        )

    session.execute.assert_not_called()
    
def test_mark_failed_rejects_non_string_error_message() -> None:
    session = Mock(spec=Session)

    repository = SqlAlchemyRawPayloadRepository(
        session=session,
    )

    with pytest.raises(TypeError):
        repository.mark_failed(
            payload_id=uuid4(),
            error_message=None,  # type: ignore[arg-type]
        )

    session.execute.assert_not_called()