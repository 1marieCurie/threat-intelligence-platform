from __future__ import annotations

import logging
from unittest.mock import Mock

import pytest

from application.services.cwe_catalog_sync_service import (
    CWECatalogSyncResult,
)
from infrastructure.adapters.inbound.cwe_catalog_sync_job import (
    CWECatalogSyncJob,
)


def _result(
    *,
    requested_ids: int = 3,
    fetched_weaknesses: int = 3,
    persisted_weaknesses: int = 3,
    batches: int = 1,
    missing_ids: tuple[str, ...] = (),
) -> CWECatalogSyncResult:
    return CWECatalogSyncResult(
        catalog_version="4.20",
        catalog_date="2026-04-30",
        requested_ids=requested_ids,
        fetched_weaknesses=(
            fetched_weaknesses
        ),
        persisted_weaknesses=(
            persisted_weaknesses
        ),
        batches=batches,
        missing_ids=missing_ids,
    )


def test_constructor_rejects_missing_service(
) -> None:
    with pytest.raises(
        ValueError,
        match="sync_service must not be None",
    ):
        CWECatalogSyncJob(
            sync_service=None,  # type: ignore[arg-type]
        )


def test_run_delegates_to_service(
) -> None:
    service = Mock()

    expected_result = _result()

    service.synchronize_referenced.return_value = (
        expected_result
    )

    job = CWECatalogSyncJob(
        sync_service=service,
    )

    result = job.run()

    service.synchronize_referenced \
        .assert_called_once_with()

    assert result is expected_result


def test_run_logs_completion_counters(
    caplog: pytest.LogCaptureFixture,
) -> None:
    service = Mock()

    service.synchronize_referenced.return_value = (
        _result(
            requested_ids=5,
            fetched_weaknesses=3,
            persisted_weaknesses=3,
            batches=2,
            missing_ids=(
                "CWE-999",
                "CWE-1000",
            ),
        )
    )

    job = CWECatalogSyncJob(
        sync_service=service,
    )

    with caplog.at_level(
        logging.INFO
    ):
        job.run()

    completed_record = next(
        record
        for record in caplog.records
        if record.getMessage()
        == (
            "CWE catalog "
            "synchronization completed"
        )
    )

    assert (
        completed_record.__dict__[
            "catalog_version"
        ]
        == "4.20"
    )

    assert (
        completed_record.__dict__[
            "requested_ids"
        ]
        == 5
    )

    assert (
        completed_record.__dict__[
            "fetched_weaknesses"
        ]
        == 3
    )

    assert (
        completed_record.__dict__[
            "persisted_weaknesses"
        ]
        == 3
    )

    assert (
        completed_record.__dict__[
            "batches"
        ]
        == 2
    )

    assert (
        completed_record.__dict__[
            "missing_ids_count"
        ]
        == 2
    )

    assert "CWE-999" not in caplog.text
    assert "CWE-1000" not in caplog.text


def test_run_logs_empty_synchronization(
    caplog: pytest.LogCaptureFixture,
) -> None:
    service = Mock()

    service.synchronize_referenced.return_value = (
        CWECatalogSyncResult(
            catalog_version=None,
            catalog_date=None,
            requested_ids=0,
            fetched_weaknesses=0,
            persisted_weaknesses=0,
            batches=0,
        )
    )

    job = CWECatalogSyncJob(
        sync_service=service,
    )

    with caplog.at_level(
        logging.INFO
    ):
        result = job.run()

    assert result.requested_ids == 0
    assert result.batches == 0

    completed_record = next(
        record
        for record in caplog.records
        if record.getMessage()
        == (
            "CWE catalog "
            "synchronization completed"
        )
    )

    assert (
        completed_record.__dict__[
            "missing_ids_count"
        ]
        == 0
    )


def test_run_redacts_failure_and_propagates(
    caplog: pytest.LogCaptureFixture,
) -> None:
    service = Mock()

    service.synchronize_referenced.side_effect = (
        RuntimeError(
            "DATABASE_URL="
            "postgresql://user:"
            "super-secret-password@localhost/db"
        )
    )

    job = CWECatalogSyncJob(
        sync_service=service,
    )

    with caplog.at_level(
        logging.ERROR
    ):
        with pytest.raises(
            RuntimeError,
            match="super-secret-password",
        ):
            job.run()

    failure_record = next(
        record
        for record in caplog.records
        if record.getMessage()
        == (
            "CWE catalog "
            "synchronization failed"
        )
    )

    error_summary = (
        failure_record.__dict__[
            "error_summary"
        ]
    )

    assert (
        "super-secret-password"
        not in error_summary
    )

    assert "[REDACTED]" in error_summary

    assert (
        "super-secret-password"
        not in caplog.text
    )

    assert failure_record.exc_info is None
    