from __future__ import annotations

import logging
from unittest.mock import (
    Mock,
    call,
)
from uuid import uuid4

import pytest

from application.services.urlhaus_normalization_service import (
    URLhausNormalizationResult,
)
from infrastructure.adapters.inbound.urlhaus_normalization_job import (
    URLhausNormalizationJob,
    URLhausNormalizationJobResult,
)


def _result(
    *,
    claimed: int = 0,
    normalized: int = 0,
    already_normalized: int = 0,
    failed: int = 0,
    requeued: int = 0,
    stale_failed: int = 0,
) -> URLhausNormalizationResult:
    return URLhausNormalizationResult(
        claimed=claimed,
        normalized=normalized,
        already_normalized=(
            already_normalized
        ),
        failed=failed,
        requeued=requeued,
        stale_failed=stale_failed,
    )


def test_constructor_rejects_missing_service(
) -> None:
    with pytest.raises(
        ValueError,
        match="normalization_service",
    ):
        URLhausNormalizationJob(
            normalization_service=None,  # type: ignore[arg-type]
            source_id=uuid4(),
            source_code="URLHAUS",
        )


@pytest.mark.parametrize(
    (
        "field_name",
        "invalid_value",
        "error_type",
    ),
    [
        (
            "batch_size",
            True,
            TypeError,
        ),
        (
            "batch_size",
            0,
            ValueError,
        ),
        (
            "batch_size",
            1_001,
            ValueError,
        ),
        (
            "max_batches",
            "10",
            TypeError,
        ),
        (
            "max_batches",
            -1,
            ValueError,
        ),
    ],
)
def test_constructor_rejects_invalid_limits(
    field_name: str,
    invalid_value: object,
    error_type: type[Exception],
) -> None:
    arguments: dict[
        str,
        object,
    ] = {
        "normalization_service": Mock(),
        "source_id": uuid4(),
        "source_code": "URLHAUS",
        field_name: invalid_value,
    }

    with pytest.raises(
        error_type,
        match=field_name,
    ):
        URLhausNormalizationJob(
            **arguments,  # type: ignore[arg-type]
        )


def test_run_stops_on_empty_batch(
) -> None:
    source_id = uuid4()
    service = Mock()

    service.process_pending.return_value = (
        _result()
    )

    job = URLhausNormalizationJob(
        normalization_service=service,
        source_id=source_id,
        source_code="urlhaus",
        batch_size=25,
    )

    result = job.run()

    service.process_pending \
        .assert_called_once_with(
            source_id=source_id,
            limit=25,
        )

    assert result == (
        URLhausNormalizationJobResult(
            batches=0,
            claimed=0,
            normalized=0,
            already_normalized=0,
            failed=0,
            requeued=0,
            stale_failed=0,
        )
    )


def test_run_aggregates_multiple_batches(
) -> None:
    source_id = uuid4()
    service = Mock()

    service.process_pending.side_effect = [
        _result(
            claimed=3,
            normalized=2,
            already_normalized=1,
            requeued=1,
        ),
        _result(
            claimed=2,
            normalized=1,
            failed=1,
            stale_failed=1,
        ),
        _result(
            requeued=2,
        ),
    ]

    job = URLhausNormalizationJob(
        normalization_service=service,
        source_id=source_id,
        source_code="URLHAUS",
        batch_size=3,
    )

    result = job.run()

    assert (
        service
        .process_pending
        .call_args_list
        == [
            call(
                source_id=source_id,
                limit=3,
            ),
            call(
                source_id=source_id,
                limit=3,
            ),
            call(
                source_id=source_id,
                limit=3,
            ),
        ]
    )

    assert result == (
        URLhausNormalizationJobResult(
            batches=2,
            claimed=5,
            normalized=3,
            already_normalized=1,
            failed=1,
            requeued=3,
            stale_failed=1,
        )
    )


def test_run_rejects_unbounded_cycle(
) -> None:
    service = Mock()

    service.process_pending.return_value = (
        _result(
            claimed=1,
            normalized=1,
        )
    )

    job = URLhausNormalizationJob(
        normalization_service=service,
        source_id=uuid4(),
        source_code="URLHAUS",
        batch_size=1,
        max_batches=2,
    )

    with pytest.raises(
        RuntimeError,
        match="max_batches",
    ):
        job.run()

    assert (
        service.process_pending.call_count
        == 2
    )


def test_failure_log_does_not_expose_ioc(
    caplog: pytest.LogCaptureFixture,
) -> None:
    sensitive_url = (
        "https://user:password@"
        "example.invalid/malware?"
        "access_token=secret-value"
    )

    service = Mock()

    service.process_pending.side_effect = (
        RuntimeError(
            f"database failure: "
            f"{sensitive_url}"
        )
    )

    job = URLhausNormalizationJob(
        normalization_service=service,
        source_id=uuid4(),
        source_code="URLHAUS",
    )

    with caplog.at_level(
        logging.ERROR
    ):
        with pytest.raises(
            RuntimeError,
        ):
            job.run()

    record = next(
        log_record
        for log_record in caplog.records
        if log_record.getMessage()
        == "URLhaus normalization failed"
    )

    summary = record.__dict__[
        "error_summary"
    ]

    assert sensitive_url not in summary
    assert "password" not in summary
    assert "secret-value" not in summary

    assert summary == (
        "RuntimeError: unexpected "
        "normalization job failure"
    )

    assert record.exc_info is None