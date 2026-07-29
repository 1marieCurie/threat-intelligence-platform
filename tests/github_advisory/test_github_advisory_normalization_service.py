from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import MagicMock, Mock
from uuid import UUID, uuid4

import pytest

from application.ports.outbound.github_advisory_vulnerability_repository import (
    GitHubAdvisoryVulnerabilityData,
)
from application.ports.outbound.raw_payload_repository import (
    RawPayloadRecoveryResult,
)
from application.services.github_advisory_normalization_service import (
    GitHubAdvisoryNormalizationService,
)
from application.services.github_advisory_normalizer import (
    GitHubAdvisoryNormalizationError,
    GitHubAdvisoryNormalizer,
)


@dataclass(frozen=True, slots=True)
class FakeClaimedPayload:
    id: UUID
    payload: dict[str, Any]


def _build_unit_of_work() -> MagicMock:
    unit_of_work = MagicMock()

    unit_of_work.__enter__.return_value = (
        unit_of_work
    )
    unit_of_work.__exit__.return_value = False

    unit_of_work.raw_payloads = Mock()

    unit_of_work.github_advisory_vulnerabilities = (
        Mock()
    )

    unit_of_work.raw_payloads \
        .recover_stale_processing \
        .return_value = RawPayloadRecoveryResult(
            requeued=0,
            failed=0,
        )

    return unit_of_work


def _build_normalized_data(
    payload_id: UUID,
) -> GitHubAdvisoryVulnerabilityData:
    return GitHubAdvisoryVulnerabilityData(
        raw_payload_id=payload_id,
        ghsa_id="GHSA-aaaa-bbbb-cccc",
        cve_id="CVE-2026-12345",
        advisory_type="reviewed",
        severity="HIGH",
        summary="Test advisory",
        description=(
            "Normalized GitHub Advisory."
        ),
        normalizer_version="1.0.0",
    )


def test_process_pending_normalizes_payload(
) -> None:
    source_id = uuid4()
    payload_id = uuid4()

    raw_payload = FakeClaimedPayload(
        id=payload_id,
        payload={
            "ghsa_id": (
                "GHSA-aaaa-bbbb-cccc"
            ),
            "cve_id": "CVE-2026-12345",
        },
    )

    unit_of_work = _build_unit_of_work()

    normalizer = Mock(
        spec=GitHubAdvisoryNormalizer,
    )

    normalized_data = (
        _build_normalized_data(
            payload_id
        )
    )

    unit_of_work.raw_payloads \
        .claim_pending.return_value = [
            raw_payload
        ]

    unit_of_work \
        .github_advisory_vulnerabilities \
        .exists_by_raw_payload_id \
        .return_value = False

    unit_of_work.raw_payloads \
        .mark_processed.return_value = True

    normalizer.normalize.return_value = (
        normalized_data
    )

    service = (
        GitHubAdvisoryNormalizationService(
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

    unit_of_work.raw_payloads \
        .recover_stale_processing \
        .assert_called_once()

    unit_of_work.raw_payloads \
        .claim_pending \
        .assert_called_once_with(
            source_id=source_id,
            limit=10,
        )

    normalizer.normalize \
        .assert_called_once_with(
            raw_payload_id=payload_id,
            payload=raw_payload.payload,
        )

    unit_of_work \
        .github_advisory_vulnerabilities \
        .save.assert_called_once_with(
            normalized_data
        )

    unit_of_work.raw_payloads \
        .mark_processed \
        .assert_called_once_with(
            payload_id=payload_id
        )

    # 1. récupération des leases
    # 2. réservation du lot
    # 3. sauvegarde et passage à processed
    assert unit_of_work.commit.call_count == 3


def test_existing_normalized_payload_is_repaired(
) -> None:
    source_id = uuid4()
    payload_id = uuid4()

    raw_payload = FakeClaimedPayload(
        id=payload_id,
        payload={},
    )

    unit_of_work = _build_unit_of_work()

    normalizer = Mock(
        spec=GitHubAdvisoryNormalizer,
    )

    unit_of_work.raw_payloads \
        .claim_pending.return_value = [
            raw_payload
        ]

    unit_of_work \
        .github_advisory_vulnerabilities \
        .exists_by_raw_payload_id \
        .return_value = True

    unit_of_work.raw_payloads \
        .mark_processed.return_value = True

    service = (
        GitHubAdvisoryNormalizationService(
            unit_of_work=unit_of_work,
            normalizer=normalizer,
        )
    )

    result = service.process_pending(
        source_id=source_id,
    )

    assert result.claimed == 1
    assert result.normalized == 0
    assert result.already_normalized == 1
    assert result.failed == 0
    assert result.requeued == 0
    assert result.stale_failed == 0

    normalizer.normalize.assert_not_called()

    unit_of_work \
        .github_advisory_vulnerabilities \
        .save.assert_not_called()

    unit_of_work.raw_payloads \
        .mark_processed \
        .assert_called_once_with(
            payload_id=payload_id
        )

    assert unit_of_work.commit.call_count == 3


def test_invalid_payload_is_marked_failed(
) -> None:
    source_id = uuid4()
    payload_id = uuid4()

    raw_payload = FakeClaimedPayload(
        id=payload_id,
        payload={},
    )

    unit_of_work = _build_unit_of_work()

    normalizer = Mock(
        spec=GitHubAdvisoryNormalizer,
    )

    unit_of_work.raw_payloads \
        .claim_pending.return_value = [
            raw_payload
        ]

    unit_of_work \
        .github_advisory_vulnerabilities \
        .exists_by_raw_payload_id \
        .return_value = False

    normalizer.normalize.side_effect = (
        GitHubAdvisoryNormalizationError(
            "authorization: Bearer "
            "secret-github-token"
        )
    )

    unit_of_work.raw_payloads \
        .mark_failed.return_value = True

    service = (
        GitHubAdvisoryNormalizationService(
            unit_of_work=unit_of_work,
            normalizer=normalizer,
        )
    )

    result = service.process_pending(
        source_id=source_id,
    )

    assert result.claimed == 1
    assert result.normalized == 0
    assert result.already_normalized == 0
    assert result.failed == 1
    assert result.requeued == 0
    assert result.stale_failed == 0

    failure_call = (
        unit_of_work.raw_payloads
        .mark_failed.call_args
    )

    assert failure_call is not None

    assert failure_call.kwargs[
        "payload_id"
    ] == payload_id

    error_message = failure_call.kwargs[
        "error_message"
    ]

    assert (
        "secret-github-token"
        not in error_message
    )
    assert "[REDACTED]" in error_message

    unit_of_work \
        .github_advisory_vulnerabilities \
        .save.assert_not_called()

    unit_of_work.raw_payloads \
        .mark_processed.assert_not_called()

    assert unit_of_work.commit.call_count == 3


def test_empty_batch_returns_zero_counts(
) -> None:
    unit_of_work = _build_unit_of_work()

    normalizer = Mock(
        spec=GitHubAdvisoryNormalizer,
    )

    unit_of_work.raw_payloads \
        .claim_pending.return_value = []

    service = (
        GitHubAdvisoryNormalizationService(
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
        .github_advisory_vulnerabilities \
        .save.assert_not_called()

    unit_of_work.raw_payloads \
        .mark_processed.assert_not_called()

    unit_of_work.raw_payloads \
        .mark_failed.assert_not_called()

    # Récupération des leases puis
    # réservation du lot vide.
    assert unit_of_work.commit.call_count == 2


def test_process_pending_recovers_stale_payloads(
) -> None:
    source_id = uuid4()

    unit_of_work = _build_unit_of_work()

    normalizer = Mock(
        spec=GitHubAdvisoryNormalizer,
    )

    unit_of_work.raw_payloads \
        .recover_stale_processing \
        .return_value = RawPayloadRecoveryResult(
            requeued=2,
            failed=1,
        )

    unit_of_work.raw_payloads \
        .claim_pending.return_value = []

    service = (
        GitHubAdvisoryNormalizationService(
            unit_of_work=unit_of_work,
            normalizer=normalizer,
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

    assert result.claimed == 0
    assert result.normalized == 0
    assert result.already_normalized == 0
    assert result.failed == 0
    assert result.requeued == 2
    assert result.stale_failed == 1

    recovery_call = (
        unit_of_work.raw_payloads
        .recover_stale_processing
        .call_args
    )

    assert recovery_call is not None

    assert recovery_call.kwargs[
        "source_id"
    ] == source_id

    assert recovery_call.kwargs[
        "max_attempts"
    ] == 3

    assert recovery_call.kwargs[
        "failure_message"
    ] == (
        "Processing lease expired "
        "after maximum attempts"
    )

    stale_before = recovery_call.kwargs[
        "stale_before"
    ]

    assert isinstance(
        stale_before,
        datetime,
    )

    assert stale_before.tzinfo is not None

    assert (
        started_at
        - timedelta(minutes=31)
        <= stale_before
        <= finished_at
        - timedelta(minutes=29)
    )

    unit_of_work.raw_payloads \
        .claim_pending \
        .assert_called_once_with(
            source_id=source_id,
            limit=10,
        )

    method_names = [
        method_call[0]
        for method_call
        in unit_of_work.raw_payloads.method_calls
    ]

    assert method_names[:2] == [
        "recover_stale_processing",
        "claim_pending",
    ]

    normalizer.normalize.assert_not_called()

    assert unit_of_work.commit.call_count == 2


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
    unit_of_work = _build_unit_of_work()

    service = (
        GitHubAdvisoryNormalizationService(
            unit_of_work=unit_of_work,
            normalizer=Mock(
                spec=GitHubAdvisoryNormalizer,
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

    unit_of_work.raw_payloads \
        .recover_stale_processing \
        .assert_not_called()

    unit_of_work.raw_payloads \
        .claim_pending.assert_not_called()


@pytest.mark.parametrize(
    "invalid_limit",
    [
        0,
        -1,
    ],
)
def test_non_positive_limit_is_rejected(
    invalid_limit: int,
) -> None:
    unit_of_work = _build_unit_of_work()

    service = (
        GitHubAdvisoryNormalizationService(
            unit_of_work=unit_of_work,
            normalizer=Mock(
                spec=GitHubAdvisoryNormalizer,
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

    unit_of_work.raw_payloads \
        .recover_stale_processing \
        .assert_not_called()

    unit_of_work.raw_payloads \
        .claim_pending.assert_not_called()


def test_invalid_source_id_is_rejected(
) -> None:
    unit_of_work = _build_unit_of_work()

    service = (
        GitHubAdvisoryNormalizationService(
            unit_of_work=unit_of_work,
            normalizer=Mock(
                spec=GitHubAdvisoryNormalizer,
            ),
        )
    )

    with pytest.raises(
        TypeError,
        match="source_id",
    ):
        service.process_pending(
            source_id=(
                "invalid"
            ),  # type: ignore[arg-type]
        )

    unit_of_work.raw_payloads \
        .recover_stale_processing \
        .assert_not_called()

    unit_of_work.raw_payloads \
        .claim_pending.assert_not_called()


@pytest.mark.parametrize(
    "invalid_timeout",
    [
        timedelta(seconds=0),
        timedelta(seconds=-1),
    ],
)
def test_constructor_rejects_non_positive_lease_timeout(
    invalid_timeout: timedelta,
) -> None:
    with pytest.raises(
        ValueError,
        match="lease_timeout",
    ):
        GitHubAdvisoryNormalizationService(
            unit_of_work=_build_unit_of_work(),
            normalizer=Mock(
                spec=GitHubAdvisoryNormalizer,
            ),
            lease_timeout=invalid_timeout,
        )


def test_constructor_rejects_invalid_lease_timeout_type(
) -> None:
    with pytest.raises(
        TypeError,
        match="lease_timeout",
    ):
        GitHubAdvisoryNormalizationService(
            unit_of_work=_build_unit_of_work(),
            normalizer=Mock(
                spec=GitHubAdvisoryNormalizer,
            ),
            lease_timeout=(
                30
            ),  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "invalid_max_attempts",
    [
        True,
        "3",
        None,
    ],
)
def test_constructor_rejects_invalid_max_attempts_type(
    invalid_max_attempts: object,
) -> None:
    with pytest.raises(
        TypeError,
        match="max_attempts",
    ):
        GitHubAdvisoryNormalizationService(
            unit_of_work=_build_unit_of_work(),
            normalizer=Mock(
                spec=GitHubAdvisoryNormalizer,
            ),
            max_attempts=(
                invalid_max_attempts
            ),  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "invalid_max_attempts",
    [
        0,
        -1,
    ],
)
def test_constructor_rejects_non_positive_max_attempts(
    invalid_max_attempts: int,
) -> None:
    with pytest.raises(
        ValueError,
        match="max_attempts",
    ):
        GitHubAdvisoryNormalizationService(
            unit_of_work=_build_unit_of_work(),
            normalizer=Mock(
                spec=GitHubAdvisoryNormalizer,
            ),
            max_attempts=invalid_max_attempts,
        )


def test_constructor_rejects_missing_unit_of_work(
) -> None:
    with pytest.raises(
        ValueError,
        match="unit_of_work",
    ):
        GitHubAdvisoryNormalizationService(
            unit_of_work=(
                None
            ),  # type: ignore[arg-type]
            normalizer=Mock(
                spec=GitHubAdvisoryNormalizer,
            ),
        )


def test_constructor_rejects_missing_normalizer(
) -> None:
    with pytest.raises(
        ValueError,
        match="normalizer",
    ):
        GitHubAdvisoryNormalizationService(
            unit_of_work=_build_unit_of_work(),
            normalizer=(
                None
            ),  # type: ignore[arg-type]
        )