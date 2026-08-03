from __future__ import annotations

from dataclasses import dataclass
from datetime import (
    UTC,
    datetime,
    timedelta,
)
from typing import Any
from unittest.mock import (
    MagicMock,
    Mock,
)
from uuid import (
    UUID,
    uuid4,
)

import pytest

from application.ports.outbound.raw_payload_repository import (
    RawPayloadRecoveryResult,
)
from application.ports.outbound.urlhaus_url_repository import (
    URLhausURLData,
)
from application.services.urlhaus_normalization_service import (
    URLhausNormalizationService,
)
from application.services.urlhaus_normalizer import (
    URLhausNormalizationError,
    URLhausNormalizer,
)


@dataclass(
    frozen=True,
    slots=True,
)
class FakeClaimedPayload:
    id: UUID
    payload: dict[str, Any]


def _build_unit_of_work() -> MagicMock:
    unit_of_work = MagicMock()

    unit_of_work.__enter__.return_value = (
        unit_of_work
    )

    unit_of_work.__exit__.return_value = (
        False
    )

    unit_of_work.raw_payloads = Mock()
    unit_of_work.urlhaus_urls = Mock()

    unit_of_work \
        .raw_payloads \
        .recover_stale_processing \
        .return_value = (
            RawPayloadRecoveryResult(
                requeued=0,
                failed=0,
            )
        )

    return unit_of_work


def _build_normalized_data(
    payload_id: UUID,
) -> URLhausURLData:
    return URLhausURLData(
        raw_payload_id=payload_id,
        urlhaus_id=3_886_372,
        malicious_url=(
            "https://example.invalid/"
            "malware"
        ),
        hostname="example.invalid",
        url_status="online",
        normalizer_version="1.0.0",
    )


def test_process_pending_normalizes_payload(
) -> None:
    source_id = uuid4()
    payload_id = uuid4()

    raw_payload = FakeClaimedPayload(
        id=payload_id,
        payload={
            "id": 3_886_372,
            "url": (
                "https://example.invalid/"
                "malware"
            ),
        },
    )

    unit_of_work = (
        _build_unit_of_work()
    )

    normalizer = Mock(
        spec=URLhausNormalizer,
    )

    normalized_data = (
        _build_normalized_data(
            payload_id
        )
    )

    unit_of_work \
        .raw_payloads \
        .claim_pending \
        .return_value = [
            raw_payload
        ]

    unit_of_work \
        .urlhaus_urls \
        .exists_by_raw_payload_id \
        .side_effect = [
            False,
            False,
        ]

    unit_of_work \
        .raw_payloads \
        .mark_processed \
        .return_value = True

    normalizer.normalize.return_value = (
        normalized_data
    )

    service = (
        URLhausNormalizationService(
            unit_of_work=unit_of_work,
            normalizer=normalizer,
        )
    )

    result = service.process_pending(
        source_id=source_id,
        limit=10,
    )

    assert result.claimed == 1
    assert result.normalized == 1
    assert result.already_normalized == 0
    assert result.failed == 0
    assert result.requeued == 0
    assert result.stale_failed == 0

    unit_of_work \
        .raw_payloads \
        .claim_pending \
        .assert_called_once_with(
            source_id=source_id,
            limit=10,
        )

    normalizer \
        .normalize \
        .assert_called_once_with(
            raw_payload_id=payload_id,
            payload=raw_payload.payload,
        )

    unit_of_work \
        .urlhaus_urls \
        .save \
        .assert_called_once_with(
            normalized_data
        )

    unit_of_work \
        .raw_payloads \
        .mark_processed \
        .assert_called_once_with(
            payload_id=payload_id
        )

    # Récupération, claim et persistance finale.
    assert (
        unit_of_work.commit.call_count
        == 3
    )


def test_existing_normalized_payload_is_repaired(
) -> None:
    payload_id = uuid4()

    raw_payload = FakeClaimedPayload(
        id=payload_id,
        payload={},
    )

    unit_of_work = (
        _build_unit_of_work()
    )

    normalizer = Mock(
        spec=URLhausNormalizer,
    )

    unit_of_work \
        .raw_payloads \
        .claim_pending \
        .return_value = [
            raw_payload
        ]

    unit_of_work \
        .urlhaus_urls \
        .exists_by_raw_payload_id \
        .return_value = True

    unit_of_work \
        .raw_payloads \
        .mark_processed \
        .return_value = True

    service = (
        URLhausNormalizationService(
            unit_of_work=unit_of_work,
            normalizer=normalizer,
        )
    )

    result = service.process_pending(
        source_id=uuid4(),
    )

    assert result.claimed == 1
    assert result.normalized == 0
    assert result.already_normalized == 1
    assert result.failed == 0

    normalizer.normalize.assert_not_called()

    unit_of_work \
        .urlhaus_urls \
        .save \
        .assert_not_called()

    unit_of_work \
        .raw_payloads \
        .mark_processed \
        .assert_called_once_with(
            payload_id=payload_id
        )

    assert (
        unit_of_work.commit.call_count
        == 3
    )


def test_concurrent_normalization_is_detected(
) -> None:
    payload_id = uuid4()

    raw_payload = FakeClaimedPayload(
        id=payload_id,
        payload={
            "id": 3_886_372,
            "url": (
                "https://example.invalid/"
                "malware"
            ),
        },
    )

    unit_of_work = (
        _build_unit_of_work()
    )

    normalizer = Mock(
        spec=URLhausNormalizer,
    )

    normalizer.normalize.return_value = (
        _build_normalized_data(
            payload_id
        )
    )

    unit_of_work \
        .raw_payloads \
        .claim_pending \
        .return_value = [
            raw_payload
        ]

    unit_of_work \
        .urlhaus_urls \
        .exists_by_raw_payload_id \
        .side_effect = [
            False,
            True,
        ]

    unit_of_work \
        .raw_payloads \
        .mark_processed \
        .return_value = True

    service = (
        URLhausNormalizationService(
            unit_of_work=unit_of_work,
            normalizer=normalizer,
        )
    )

    result = service.process_pending(
        source_id=uuid4(),
    )

    assert result.normalized == 0
    assert result.already_normalized == 1
    assert result.failed == 0

    normalizer.normalize.assert_called_once()

    unit_of_work \
        .urlhaus_urls \
        .save \
        .assert_not_called()


def test_invalid_payload_is_marked_failed(
) -> None:
    payload_id = uuid4()

    raw_payload = FakeClaimedPayload(
        id=payload_id,
        payload={},
    )

    unit_of_work = (
        _build_unit_of_work()
    )

    normalizer = Mock(
        spec=URLhausNormalizer,
    )

    unit_of_work \
        .raw_payloads \
        .claim_pending \
        .return_value = [
            raw_payload
        ]

    unit_of_work \
        .urlhaus_urls \
        .exists_by_raw_payload_id \
        .return_value = False

    normalizer.normalize.side_effect = (
        URLhausNormalizationError(
            "authorization: "
            "Bearer secret-token"
        )
    )

    unit_of_work \
        .raw_payloads \
        .mark_failed \
        .return_value = True

    service = (
        URLhausNormalizationService(
            unit_of_work=unit_of_work,
            normalizer=normalizer,
        )
    )

    result = service.process_pending(
        source_id=uuid4(),
    )

    assert result.claimed == 1
    assert result.normalized == 0
    assert result.failed == 1

    call = (
        unit_of_work
        .raw_payloads
        .mark_failed
        .call_args
    )

    assert (
        call.kwargs["payload_id"]
        == payload_id
    )

    error_message = (
        call.kwargs["error_message"]
    )

    assert (
        "secret-token"
        not in error_message
    )

    assert (
        "[REDACTED]"
        in error_message
    )

    unit_of_work \
        .urlhaus_urls \
        .save \
        .assert_not_called()

    assert (
        unit_of_work.commit.call_count
        == 3
    )


def test_unexpected_error_does_not_expose_ioc(
) -> None:
    payload_id = uuid4()

    sensitive_url = (
        "https://user:password@"
        "example.invalid/malware?"
        "access_token=secret-value"
    )

    raw_payload = FakeClaimedPayload(
        id=payload_id,
        payload={
            "id": 1,
            "url": sensitive_url,
        },
    )

    unit_of_work = (
        _build_unit_of_work()
    )

    normalizer = Mock(
        spec=URLhausNormalizer,
    )

    unit_of_work \
        .raw_payloads \
        .claim_pending \
        .return_value = [
            raw_payload
        ]

    unit_of_work \
        .urlhaus_urls \
        .exists_by_raw_payload_id \
        .return_value = False

    normalizer.normalize.side_effect = (
        RuntimeError(
            f"database failure: {sensitive_url}"
        )
    )

    unit_of_work \
        .raw_payloads \
        .mark_failed \
        .return_value = True

    service = (
        URLhausNormalizationService(
            unit_of_work=unit_of_work,
            normalizer=normalizer,
        )
    )

    result = service.process_pending(
        source_id=uuid4(),
    )

    assert result.failed == 1

    error_message = (
        unit_of_work
        .raw_payloads
        .mark_failed
        .call_args
        .kwargs["error_message"]
    )

    assert sensitive_url not in error_message
    assert "password" not in error_message
    assert "secret-value" not in error_message

    assert error_message == (
        "RuntimeError: unexpected "
        "normalization failure"
    )


def test_empty_batch_returns_zero_counts(
) -> None:
    unit_of_work = (
        _build_unit_of_work()
    )

    normalizer = Mock(
        spec=URLhausNormalizer,
    )

    unit_of_work \
        .raw_payloads \
        .claim_pending \
        .return_value = []

    service = (
        URLhausNormalizationService(
            unit_of_work=unit_of_work,
            normalizer=normalizer,
        )
    )

    result = service.process_pending(
        source_id=uuid4(),
    )

    assert result.claimed == 0
    assert result.normalized == 0
    assert result.already_normalized == 0
    assert result.failed == 0
    assert result.requeued == 0
    assert result.stale_failed == 0

    normalizer.normalize.assert_not_called()

    unit_of_work \
        .urlhaus_urls \
        .save \
        .assert_not_called()

    assert (
        unit_of_work.commit.call_count
        == 2
    )


def test_stale_payloads_are_recovered(
) -> None:
    source_id = uuid4()

    unit_of_work = (
        _build_unit_of_work()
    )

    unit_of_work \
        .raw_payloads \
        .recover_stale_processing \
        .return_value = (
            RawPayloadRecoveryResult(
                requeued=2,
                failed=1,
            )
        )

    unit_of_work \
        .raw_payloads \
        .claim_pending \
        .return_value = []

    service = (
        URLhausNormalizationService(
            unit_of_work=unit_of_work,
            normalizer=Mock(
                spec=URLhausNormalizer,
            ),
            lease_timeout=timedelta(
                minutes=30
            ),
            max_attempts=3,
        )
    )

    started_at = datetime.now(UTC)

    result = service.process_pending(
        source_id=source_id,
        limit=10,
    )

    finished_at = datetime.now(UTC)

    assert result.requeued == 2
    assert result.stale_failed == 1

    recovery_call = (
        unit_of_work
        .raw_payloads
        .recover_stale_processing
        .call_args
    )

    assert (
        recovery_call.kwargs["source_id"]
        == source_id
    )

    assert (
        recovery_call.kwargs["max_attempts"]
        == 3
    )

    assert recovery_call.kwargs[
        "failure_message"
    ] == (
        "Processing lease expired "
        "after maximum attempts"
    )

    stale_before = (
        recovery_call.kwargs[
            "stale_before"
        ]
    )

    assert (
        started_at
        - timedelta(minutes=31)
        <= stale_before
        <= finished_at
        - timedelta(minutes=29)
    )


@pytest.mark.parametrize(
    "invalid_limit",
    [
        True,
        "10",
        None,
    ],
)
def test_invalid_limit_type_is_rejected(
    invalid_limit: object,
) -> None:
    unit_of_work = (
        _build_unit_of_work()
    )

    service = (
        URLhausNormalizationService(
            unit_of_work=unit_of_work,
            normalizer=Mock(
                spec=URLhausNormalizer,
            ),
        )
    )

    with pytest.raises(
        TypeError,
        match="limit",
    ):
        service.process_pending(
            source_id=uuid4(),
            limit=invalid_limit,  # type: ignore[arg-type]
        )

    unit_of_work \
        .raw_payloads \
        .claim_pending \
        .assert_not_called()


@pytest.mark.parametrize(
    "invalid_limit",
    [
        0,
        -1,
        1_001,
    ],
)
def test_invalid_limit_value_is_rejected(
    invalid_limit: int,
) -> None:
    service = (
        URLhausNormalizationService(
            unit_of_work=(
                _build_unit_of_work()
            ),
            normalizer=Mock(
                spec=URLhausNormalizer,
            ),
        )
    )

    with pytest.raises(
        ValueError,
        match="limit",
    ):
        service.process_pending(
            source_id=uuid4(),
            limit=invalid_limit,
        )


def test_boundary_limit_is_accepted(
) -> None:
    unit_of_work = (
        _build_unit_of_work()
    )

    unit_of_work \
        .raw_payloads \
        .claim_pending \
        .return_value = []

    service = (
        URLhausNormalizationService(
            unit_of_work=unit_of_work,
            normalizer=Mock(
                spec=URLhausNormalizer,
            ),
        )
    )

    result = service.process_pending(
        source_id=uuid4(),
        limit=1_000,
    )

    assert result.claimed == 0


def test_invalid_source_id_is_rejected(
) -> None:
    unit_of_work = (
        _build_unit_of_work()
    )

    service = (
        URLhausNormalizationService(
            unit_of_work=unit_of_work,
            normalizer=Mock(
                spec=URLhausNormalizer,
            ),
        )
    )

    with pytest.raises(
        TypeError,
        match="source_id",
    ):
        service.process_pending(
            source_id="invalid",  # type: ignore[arg-type]
        )

    unit_of_work \
        .raw_payloads \
        .claim_pending \
        .assert_not_called()


@pytest.mark.parametrize(
    "invalid_timeout",
    [
        timedelta(seconds=0),
        timedelta(seconds=-1),
    ],
)
def test_constructor_rejects_invalid_timeout(
    invalid_timeout: timedelta,
) -> None:
    with pytest.raises(
        ValueError,
        match="lease_timeout",
    ):
        URLhausNormalizationService(
            unit_of_work=(
                _build_unit_of_work()
            ),
            normalizer=Mock(
                spec=URLhausNormalizer,
            ),
            lease_timeout=invalid_timeout,
        )


@pytest.mark.parametrize(
    "invalid_attempts",
    [
        True,
        "3",
        None,
    ],
)
def test_constructor_rejects_invalid_attempts_type(
    invalid_attempts: object,
) -> None:
    with pytest.raises(
        TypeError,
        match="max_attempts",
    ):
        URLhausNormalizationService(
            unit_of_work=(
                _build_unit_of_work()
            ),
            normalizer=Mock(
                spec=URLhausNormalizer,
            ),
            max_attempts=invalid_attempts,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "invalid_attempts",
    [
        0,
        -1,
    ],
)
def test_constructor_rejects_invalid_attempts_value(
    invalid_attempts: int,
) -> None:
    with pytest.raises(
        ValueError,
        match="max_attempts",
    ):
        URLhausNormalizationService(
            unit_of_work=(
                _build_unit_of_work()
            ),
            normalizer=Mock(
                spec=URLhausNormalizer,
            ),
            max_attempts=invalid_attempts,
        )


def test_constructor_rejects_missing_unit_of_work(
) -> None:
    with pytest.raises(
        ValueError,
        match="unit_of_work",
    ):
        URLhausNormalizationService(
            unit_of_work=None,  # type: ignore[arg-type]
            normalizer=URLhausNormalizer(),
        )


def test_constructor_rejects_missing_normalizer(
) -> None:
    with pytest.raises(
        ValueError,
        match="normalizer",
    ):
        URLhausNormalizationService(
            unit_of_work=(
                _build_unit_of_work()
            ),
            normalizer=None,  # type: ignore[arg-type]
        )