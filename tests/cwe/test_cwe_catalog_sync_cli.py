from __future__ import annotations

import logging
from unittest.mock import Mock, patch

import pytest

from application.services.cwe_catalog_sync_service import (
    CWECatalogSyncResult,
)
from infrastructure.cli.cwe_catalog_sync import (
    _parse_arguments,
    main,
)


CLI_MODULE = (
    "infrastructure.cli."
    "cwe_catalog_sync"
)


def _result(
    *,
    catalog_version: str | None = "4.20",
    catalog_date: str | None = "2026-04-30",
    requested_ids: int = 3,
    fetched_weaknesses: int = 3,
    persisted_weaknesses: int = 3,
    up_to_date_weaknesses: int = 0,
    batches: int = 1,
    missing_ids: tuple[str, ...] = (),
) -> CWECatalogSyncResult:
    return CWECatalogSyncResult(
        catalog_version=catalog_version,
        catalog_date=catalog_date,
        requested_ids=requested_ids,
        fetched_weaknesses=(
            fetched_weaknesses
        ),
        persisted_weaknesses=(
            persisted_weaknesses
        ),
        up_to_date_weaknesses=(
            up_to_date_weaknesses
        ),
        batches=batches,
        missing_ids=missing_ids,
    )


def test_parse_arguments_accepts_empty_input(
) -> None:
    arguments = _parse_arguments(
        []
    )

    assert vars(
        arguments
    ) == {}


def test_parse_arguments_rejects_unknown_argument(
) -> None:
    with pytest.raises(
        SystemExit
    ) as error:
        _parse_arguments(
            [
                "--unknown",
            ]
        )

    assert error.value.code == 2


def test_main_runs_job_and_prints_summary(
    capsys: pytest.CaptureFixture[str],
) -> None:
    job = Mock()

    job.run.return_value = _result(
        requested_ids=5,
        fetched_weaknesses=4,
        persisted_weaknesses=4,
        up_to_date_weaknesses=1,
        batches=2,
        missing_ids=(
            "CWE-999",
        ),
    )

    with (
        patch(
            f"{CLI_MODULE}."
            "configure_logging"
        ) as configure_logging,
        patch(
            f"{CLI_MODULE}."
            "build_cwe_catalog_sync_job",
            return_value=job,
        ) as build_job,
        patch(
            f"{CLI_MODULE}."
            "perf_counter",
            side_effect=[
                100.0,
                102.345,
            ],
        ),
    ):
        exit_code = main(
            []
        )

    captured = capsys.readouterr()

    assert exit_code == 0

    configure_logging.assert_called_once_with()
    build_job.assert_called_once_with()
    job.run.assert_called_once_with()

    assert (
        "CWE catalog synchronization "
        "completed"
        in captured.out
    )

    assert "requested_ids=5" in captured.out

    assert (
        "fetched_weaknesses=4"
        in captured.out
    )

    assert (
        "persisted_weaknesses=4"
        in captured.out
    )
    
    assert (
    "up_to_date_weaknesses=1"
    in captured.out
)

    assert "batches=2" in captured.out

    assert (
        "missing_ids_count=1"
        in captured.out
    )

    assert (
        "duration_seconds=2.345"
        in captured.out
    )

    assert captured.err == ""
    


def test_main_does_not_print_missing_ids(
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    job = Mock()

    job.run.return_value = _result(
        requested_ids=3,
        fetched_weaknesses=1,
        persisted_weaknesses=1,
        missing_ids=(
            "CWE-999",
            "CWE-1000",
        ),
    )

    with (
        patch(
            f"{CLI_MODULE}."
            "configure_logging"
        ),
        patch(
            f"{CLI_MODULE}."
            "build_cwe_catalog_sync_job",
            return_value=job,
        ),
        patch(
            f"{CLI_MODULE}."
            "perf_counter",
            side_effect=[
                10.0,
                11.0,
            ],
        ),
        caplog.at_level(
            logging.INFO
        ),
    ):
        exit_code = main(
            []
        )

    captured = capsys.readouterr()

    assert exit_code == 0

    assert "missing_ids_count=2" in captured.out

    assert "CWE-999" not in captured.out
    assert "CWE-1000" not in captured.out

    assert "CWE-999" not in caplog.text
    assert "CWE-1000" not in caplog.text


def test_main_handles_empty_catalog(
    capsys: pytest.CaptureFixture[str],
) -> None:
    job = Mock()

    job.run.return_value = _result(
        catalog_version=None,
        catalog_date=None,
        requested_ids=0,
        fetched_weaknesses=0,
        persisted_weaknesses=0,
        batches=0,
    )

    with (
        patch(
            f"{CLI_MODULE}."
            "configure_logging"
        ),
        patch(
            f"{CLI_MODULE}."
            "build_cwe_catalog_sync_job",
            return_value=job,
        ),
        patch(
            f"{CLI_MODULE}."
            "perf_counter",
            side_effect=[
                20.0,
                20.5,
            ],
        ),
    ):
        exit_code = main(
            []
        )

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "requested_ids=0" in captured.out
    assert "batches=0" in captured.out
    assert "catalog_version=None" in captured.out


def test_main_redacts_failure(
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    job = Mock()

    job.run.side_effect = RuntimeError(
        "DATABASE_URL="
        "postgresql://user:"
        "super-secret-password@localhost/db"
    )

    with (
        patch(
            f"{CLI_MODULE}."
            "configure_logging"
        ),
        patch(
            f"{CLI_MODULE}."
            "build_cwe_catalog_sync_job",
            return_value=job,
        ),
        caplog.at_level(
            logging.ERROR
        ),
    ):
        exit_code = main(
            []
        )

    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""

    assert (
        "CWE catalog synchronization "
        "failed"
        in captured.err
    )

    assert (
        "super-secret-password"
        not in captured.err
    )

    assert (
        "super-secret-password"
        not in caplog.text
    )

    assert "[REDACTED]" in captured.err

    failure_record = next(
        record
        for record in caplog.records
        if record.getMessage()
        == (
            "CWE catalog synchronization "
            "execution failed"
        )
    )

    assert failure_record.exc_info is None


def test_main_returns_failure_when_build_fails(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with (
        patch(
            f"{CLI_MODULE}."
            "configure_logging"
        ),
        patch(
            f"{CLI_MODULE}."
            "build_cwe_catalog_sync_job",
            side_effect=RuntimeError(
                "invalid configuration"
            ),
        ),
    ):
        exit_code = main(
            []
        )

    captured = capsys.readouterr()

    assert exit_code == 1
    assert "invalid configuration" in captured.err