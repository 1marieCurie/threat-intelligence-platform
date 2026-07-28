from __future__ import annotations

from datetime import UTC, datetime, timedelta
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


def _configure_scalars_result(
    *,
    session: Mock,
    values: list[object],
) -> None:
    execute_result = Mock()
    scalar_result = Mock()

    session.execute.return_value = execute_result
    execute_result.scalars.return_value = scalar_result
    scalar_result.all.return_value = values


def test_save_adds_payload_and_flushes_session() -> None:
    session = Mock(
        spec=Session,
    )

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

    payload_id = repository.save(
        payload
    )

    assert payload_id is not None

    session.add.assert_called_once()
    session.flush.assert_called_once_with()
    session.commit.assert_not_called()

    persisted_model = session.add.call_args.args[0]

    assert isinstance(
        persisted_model,
        SourcePayloadModel,
    )
    assert (
        persisted_model.source_id
        == payload.source_id
    )
    assert (
        persisted_model.ingestion_run_id
        == payload.ingestion_run_id
    )
    assert (
        persisted_model.external_record_id
        == "CVE-2026-0001"
    )
    assert persisted_model.payload == {
        "id": "CVE-2026-0001",
    }


def test_claim_pending_marks_payloads_as_processing() -> None:
    session = Mock(
        spec=Session,
    )

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
        external_record_id=(
            "GHSA-aaaa-bbbb-cccc"
        ),
        retrieved_at=retrieved_at,
        payload={
            "ghsa_id": (
                "GHSA-aaaa-bbbb-cccc"
            ),
        },
        payload_hash="a" * 64,
        processing_status="pending",
        processing_started_at=None,
        processing_attempts=2,
        error_message="ancienne erreur",
    )

    _configure_scalars_result(
        session=session,
        values=[model],
    )

    claimed_payloads = repository.claim_pending(
        source_id=source_id,
        limit=10,
    )

    assert len(claimed_payloads) == 1

    claimed_payload = claimed_payloads[0]

    assert claimed_payload.id == payload_id
    assert claimed_payload.source_id == source_id
    assert (
        claimed_payload.processing_status
        == "processing"
    )
    assert (
        claimed_payload.processing_started_at
        is not None
    )
    assert (
        claimed_payload.processing_started_at.tzinfo
        is not None
    )
    assert (
        claimed_payload.processing_attempts
        == 3
    )
    assert claimed_payload.error_message is None

    assert model.processing_status == "processing"
    assert model.processing_started_at is not None
    assert (
        model.processing_started_at.tzinfo
        is not None
    )
    assert model.processing_attempts == 3
    assert model.error_message is None

    assert (
        claimed_payload.processing_started_at
        == model.processing_started_at
    )

    session.execute.assert_called_once()
    session.flush.assert_called_once_with()
    session.commit.assert_not_called()


def test_claim_pending_returns_empty_sequence() -> None:
    session = Mock(
        spec=Session,
    )

    repository = SqlAlchemyRawPayloadRepository(
        session=session,
    )

    _configure_scalars_result(
        session=session,
        values=[],
    )

    claimed_payloads = repository.claim_pending(
        source_id=uuid4(),
        limit=10,
    )

    assert claimed_payloads == ()

    session.execute.assert_called_once()
    session.flush.assert_called_once_with()
    session.commit.assert_not_called()


@pytest.mark.parametrize(
    (
        "invalid_limit",
        "expected_exception",
    ),
    [
        (
            True,
            TypeError,
        ),
        (
            "10",
            TypeError,
        ),
        (
            0,
            ValueError,
        ),
        (
            -1,
            ValueError,
        ),
    ],
)
def test_claim_pending_rejects_invalid_limit(
    invalid_limit: object,
    expected_exception: type[Exception],
) -> None:
    session = Mock(
        spec=Session,
    )

    repository = SqlAlchemyRawPayloadRepository(
        session=session,
    )

    with pytest.raises(
        expected_exception,
    ):
        repository.claim_pending(
            source_id=uuid4(),
            limit=(
                invalid_limit
            ),  # type: ignore[arg-type]
        )

    session.execute.assert_not_called()
    session.flush.assert_not_called()


def test_claim_pending_rejects_invalid_source_id() -> None:
    session = Mock(
        spec=Session,
    )

    repository = SqlAlchemyRawPayloadRepository(
        session=session,
    )

    with pytest.raises(
        TypeError,
        match="source_id",
    ):
        repository.claim_pending(
            source_id=(
                "invalid"
            ),  # type: ignore[arg-type]
            limit=10,
        )

    session.execute.assert_not_called()
    session.flush.assert_not_called()


def test_mark_processed_returns_true_when_payload_is_updated() -> None:
    session = Mock(
        spec=Session,
    )

    repository = SqlAlchemyRawPayloadRepository(
        session=session,
    )

    payload_id = uuid4()

    execute_result = Mock()
    execute_result.scalar_one_or_none.return_value = (
        payload_id
    )
    session.execute.return_value = execute_result

    updated = repository.mark_processed(
        payload_id=payload_id,
    )

    assert updated is True

    session.execute.assert_called_once()
    session.commit.assert_not_called()


def test_mark_processed_returns_false_when_payload_is_not_updated() -> None:
    session = Mock(
        spec=Session,
    )

    repository = SqlAlchemyRawPayloadRepository(
        session=session,
    )

    execute_result = Mock()
    execute_result.scalar_one_or_none.return_value = (
        None
    )
    session.execute.return_value = execute_result

    updated = repository.mark_processed(
        payload_id=uuid4(),
    )

    assert updated is False

    session.execute.assert_called_once()
    session.commit.assert_not_called()


def test_mark_processed_rejects_invalid_payload_id() -> None:
    session = Mock(
        spec=Session,
    )

    repository = SqlAlchemyRawPayloadRepository(
        session=session,
    )

    with pytest.raises(
        TypeError,
        match="payload_id",
    ):
        repository.mark_processed(
            payload_id=(
                "invalid"
            ),  # type: ignore[arg-type]
        )

    session.execute.assert_not_called()


def test_mark_failed_returns_true_when_payload_is_updated() -> None:
    session = Mock(
        spec=Session,
    )

    repository = SqlAlchemyRawPayloadRepository(
        session=session,
    )

    payload_id = uuid4()

    execute_result = Mock()
    execute_result.scalar_one_or_none.return_value = (
        payload_id
    )
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
    session = Mock(
        spec=Session,
    )

    repository = SqlAlchemyRawPayloadRepository(
        session=session,
    )

    with pytest.raises(
        ValueError,
        match="error_message",
    ):
        repository.mark_failed(
            payload_id=uuid4(),
            error_message=invalid_error_message,
        )

    session.execute.assert_not_called()


def test_mark_failed_rejects_non_string_error_message() -> None:
    session = Mock(
        spec=Session,
    )

    repository = SqlAlchemyRawPayloadRepository(
        session=session,
    )

    with pytest.raises(
        TypeError,
        match="error_message",
    ):
        repository.mark_failed(
            payload_id=uuid4(),
            error_message=(
                None
            ),  # type: ignore[arg-type]
        )

    session.execute.assert_not_called()


def test_mark_failed_rejects_invalid_payload_id() -> None:
    session = Mock(
        spec=Session,
    )

    repository = SqlAlchemyRawPayloadRepository(
        session=session,
    )

    with pytest.raises(
        TypeError,
        match="payload_id",
    ):
        repository.mark_failed(
            payload_id=(
                "invalid"
            ),  # type: ignore[arg-type]
            error_message="Normalization failed",
        )

    session.execute.assert_not_called()


def test_recover_stale_processing_counts_results() -> None:
    session = Mock(
        spec=Session,
    )

    _configure_scalars_result(
        session=session,
        values=[
            "pending",
            "failed",
            "pending",
        ],
    )

    repository = SqlAlchemyRawPayloadRepository(
        session=session,
    )

    result = repository.recover_stale_processing(
        source_id=uuid4(),
        stale_before=(
            datetime.now(UTC)
            - timedelta(minutes=30)
        ),
        max_attempts=3,
        failure_message=(
            "Processing lease expired "
            "after maximum attempts"
        ),
    )

    assert result.requeued == 2
    assert result.failed == 1

    session.execute.assert_called_once()
    session.flush.assert_called_once_with()
    session.commit.assert_not_called()


def test_recover_stale_processing_returns_zero_counts() -> None:
    session = Mock(
        spec=Session,
    )

    _configure_scalars_result(
        session=session,
        values=[],
    )

    repository = SqlAlchemyRawPayloadRepository(
        session=session,
    )

    result = repository.recover_stale_processing(
        source_id=uuid4(),
        stale_before=datetime.now(UTC),
        max_attempts=3,
        failure_message=(
            "Processing lease expired"
        ),
    )

    assert result.requeued == 0
    assert result.failed == 0

    session.execute.assert_called_once()
    session.flush.assert_called_once_with()
    session.commit.assert_not_called()


def test_recover_stale_processing_rejects_invalid_source_id() -> None:
    session = Mock(
        spec=Session,
    )

    repository = SqlAlchemyRawPayloadRepository(
        session=session,
    )

    with pytest.raises(
        TypeError,
        match="source_id",
    ):
        repository.recover_stale_processing(
            source_id=(
                "invalid"
            ),  # type: ignore[arg-type]
            stale_before=datetime.now(UTC),
            max_attempts=3,
            failure_message=(
                "Processing lease expired"
            ),
        )

    session.execute.assert_not_called()
    session.flush.assert_not_called()


def test_recover_stale_processing_rejects_invalid_datetime_type() -> None:
    session = Mock(
        spec=Session,
    )

    repository = SqlAlchemyRawPayloadRepository(
        session=session,
    )

    with pytest.raises(
        TypeError,
        match="stale_before",
    ):
        repository.recover_stale_processing(
            source_id=uuid4(),
            stale_before=(
                "invalid"
            ),  # type: ignore[arg-type]
            max_attempts=3,
            failure_message=(
                "Processing lease expired"
            ),
        )

    session.execute.assert_not_called()
    session.flush.assert_not_called()


def test_recover_stale_processing_rejects_naive_datetime() -> None:
    session = Mock(
        spec=Session,
    )

    repository = SqlAlchemyRawPayloadRepository(
        session=session,
    )

    with pytest.raises(
        ValueError,
        match="timezone-aware",
    ):
        repository.recover_stale_processing(
            source_id=uuid4(),
            stale_before=datetime.now(),
            max_attempts=3,
            failure_message=(
                "Processing lease expired"
            ),
        )

    session.execute.assert_not_called()
    session.flush.assert_not_called()


@pytest.mark.parametrize(
    "invalid_max_attempts",
    [
        True,
        "3",
        None,
    ],
)
def test_recover_rejects_invalid_max_attempts_type(
    invalid_max_attempts: object,
) -> None:
    session = Mock(
        spec=Session,
    )

    repository = SqlAlchemyRawPayloadRepository(
        session=session,
    )

    with pytest.raises(
        TypeError,
        match="max_attempts",
    ):
        repository.recover_stale_processing(
            source_id=uuid4(),
            stale_before=datetime.now(UTC),
            max_attempts=(
                invalid_max_attempts
            ),  # type: ignore[arg-type]
            failure_message=(
                "Processing lease expired"
            ),
        )

    session.execute.assert_not_called()
    session.flush.assert_not_called()


@pytest.mark.parametrize(
    "invalid_max_attempts",
    [
        0,
        -1,
    ],
)
def test_recover_rejects_non_positive_max_attempts(
    invalid_max_attempts: int,
) -> None:
    session = Mock(
        spec=Session,
    )

    repository = SqlAlchemyRawPayloadRepository(
        session=session,
    )

    with pytest.raises(
        ValueError,
        match="max_attempts",
    ):
        repository.recover_stale_processing(
            source_id=uuid4(),
            stale_before=datetime.now(UTC),
            max_attempts=invalid_max_attempts,
            failure_message=(
                "Processing lease expired"
            ),
        )

    session.execute.assert_not_called()
    session.flush.assert_not_called()


@pytest.mark.parametrize(
    "invalid_failure_message",
    [
        "",
        "   ",
    ],
)
def test_recover_rejects_empty_failure_message(
    invalid_failure_message: str,
) -> None:
    session = Mock(
        spec=Session,
    )

    repository = SqlAlchemyRawPayloadRepository(
        session=session,
    )

    with pytest.raises(
        ValueError,
        match="failure_message",
    ):
        repository.recover_stale_processing(
            source_id=uuid4(),
            stale_before=datetime.now(UTC),
            max_attempts=3,
            failure_message=(
                invalid_failure_message
            ),
        )

    session.execute.assert_not_called()
    session.flush.assert_not_called()


def test_recover_rejects_non_string_failure_message() -> None:
    session = Mock(
        spec=Session,
    )

    repository = SqlAlchemyRawPayloadRepository(
        session=session,
    )

    with pytest.raises(
        TypeError,
        match="failure_message",
    ):
        repository.recover_stale_processing(
            source_id=uuid4(),
            stale_before=datetime.now(UTC),
            max_attempts=3,
            failure_message=(
                None
            ),  # type: ignore[arg-type]
        )

    session.execute.assert_not_called()
    session.flush.assert_not_called()