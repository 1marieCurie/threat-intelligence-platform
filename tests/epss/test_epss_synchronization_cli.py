from __future__ import annotations
import argparse

import logging
from datetime import date
from unittest.mock import Mock, patch

import pytest

from application.services.epss_synchronization_service import (
    EPSSSynchronizationResult,
)
from infrastructure.cli.epss_synchronization import (
    _parse_arguments,
    _parse_score_date,
    main,
)


CLI_MODULE = (
    "infrastructure.cli."
    "epss_synchronization"
)


def _result(
    *,
    requested_cves: int = 3,
    fetched_scores: int = 2,
    submitted_scores: int = 2,
    missing_cves: tuple[str, ...] = (
        "CVE-2099-0001",
    ),
    requested_score_date: date | None = None,
) -> EPSSSynchronizationResult:
    return EPSSSynchronizationResult(
        requested_cves=requested_cves,
        fetched_scores=fetched_scores,
        submitted_scores=submitted_scores,
        missing_cves=missing_cves,
        requested_score_date=requested_score_date,
    )


def test_parse_score_date_accepts_iso_date(
) -> None:
    result = _parse_score_date(
        "2026-07-29"
    )

    assert result == date(
        2026,
        7,
        29,
    )


@pytest.mark.parametrize(
    "invalid_value",
    [
        "",
        "29-07-2026",
        "2026/07/29",
        "2026-02-30",
        "invalid",
    ],
)
def test_parse_score_date_rejects_invalid_value(
    invalid_value: str,
) -> None:
    with pytest.raises(
        argparse.ArgumentTypeError,
        match=(
            "score date must use "
            "YYYY-MM-DD"
        ),
    ):
        _parse_score_date(
            invalid_value
        )
        
        
def test_parse_arguments_accepts_cves(
) -> None:
    arguments = _parse_arguments(
        [
            "CVE-2021-44228",
            "CVE-2024-3094",
        ]
    )

    assert arguments.cve_ids == [
        "CVE-2021-44228",
        "CVE-2024-3094",
    ]

    assert arguments.score_date is None


def test_parse_arguments_accepts_historical_date(
) -> None:
    arguments = _parse_arguments(
        [
            "--score-date",
            "2026-07-29",
            "CVE-2021-44228",
        ]
    )

    assert arguments.cve_ids == [
        "CVE-2021-44228",
    ]

    assert arguments.score_date == date(
        2026,
        7,
        29,
    )


def test_parse_arguments_requires_cve(
) -> None:
    with pytest.raises(
        SystemExit
    ) as error:
        _parse_arguments(
            []
        )

    assert error.value.code == 2


def test_parse_arguments_rejects_invalid_date(
) -> None:
    with pytest.raises(
        SystemExit
    ) as error:
        _parse_arguments(
            [
                "--score-date",
                "29-07-2026",
                "CVE-2021-44228",
            ]
        )

    assert error.value.code == 2


def test_main_runs_job_and_prints_summary(
    capsys: pytest.CaptureFixture[str],
) -> None:
    job = Mock()

    score_date = date(
        2026,
        7,
        29,
    )

    job.run.return_value = _result(
        requested_cves=5,
        fetched_scores=4,
        submitted_scores=4,
        missing_cves=(
            "CVE-2099-0001",
        ),
        requested_score_date=score_date,
    )

    with (
        patch(
            f"{CLI_MODULE}."
            "configure_logging"
        ) as configure_logging,
        patch(
            f"{CLI_MODULE}."
            "build_epss_synchronization_job",
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
            [
                "--score-date",
                "2026-07-29",
                "CVE-2021-44228",
                "CVE-2024-3094",
            ]
        )

    captured = capsys.readouterr()

    assert exit_code == 0

    configure_logging.assert_called_once_with()
    build_job.assert_called_once_with()

    job.run.assert_called_once_with(
        [
            "CVE-2021-44228",
            "CVE-2024-3094",
        ],
        score_date=score_date,
    )

    assert (
        "EPSS synchronization completed"
        in captured.out
    )

    assert "requested_cves=5" in captured.out
    assert "fetched_scores=4" in captured.out
    assert "submitted_scores=4" in captured.out
    assert "missing_cves_count=1" in captured.out

    assert (
        "requested_score_date=2026-07-29"
        in captured.out
    )

    assert (
        "duration_seconds=2.345"
        in captured.out
    )

    assert captured.err == ""


def test_main_does_not_print_or_log_cves(
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    job = Mock()

    requested_cve = (
        "CVE-2021-44228"
    )

    missing_cve = (
        "CVE-2099-987654"
    )

    job.run.return_value = _result(
        requested_cves=2,
        fetched_scores=1,
        submitted_scores=1,
        missing_cves=(
            missing_cve,
        ),
    )

    with (
        patch(
            f"{CLI_MODULE}."
            "configure_logging"
        ),
        patch(
            f"{CLI_MODULE}."
            "build_epss_synchronization_job",
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
            [
                requested_cve,
                missing_cve,
            ]
        )

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "missing_cves_count=1" in captured.out

    assert requested_cve not in captured.out
    assert missing_cve not in captured.out

    assert requested_cve not in captured.err
    assert missing_cve not in captured.err

    assert requested_cve not in caplog.text
    assert missing_cve not in caplog.text


def test_main_handles_empty_result(
    capsys: pytest.CaptureFixture[str],
) -> None:
    job = Mock()

    job.run.return_value = _result(
        requested_cves=0,
        fetched_scores=0,
        submitted_scores=0,
        missing_cves=(),
    )

    with (
        patch(
            f"{CLI_MODULE}."
            "configure_logging"
        ),
        patch(
            f"{CLI_MODULE}."
            "build_epss_synchronization_job",
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
            [
                "CVE-2021-44228",
            ]
        )

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "requested_cves=0" in captured.out
    assert "fetched_scores=0" in captured.out
    assert "submitted_scores=0" in captured.out
    assert "missing_cves_count=0" in captured.out


def test_main_redacts_failure(
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    job = Mock()

    secret = (
        "super-secret-password"
    )

    sensitive_cve = (
        "CVE-2021-44228"
    )

    job.run.side_effect = RuntimeError(
        "DATABASE_URL="
        "postgresql://user:"
        f"{secret}@localhost/db "
        f"while processing {sensitive_cve}"
    )

    with (
        patch(
            f"{CLI_MODULE}."
            "configure_logging"
        ),
        patch(
            f"{CLI_MODULE}."
            "build_epss_synchronization_job",
            return_value=job,
        ),
        caplog.at_level(
            logging.ERROR
        ),
    ):
        exit_code = main(
            [
                sensitive_cve,
            ]
        )

    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""

    assert (
        "EPSS synchronization failed"
        in captured.err
    )

    assert secret not in captured.err
    assert sensitive_cve not in captured.err

    assert secret not in caplog.text
    assert sensitive_cve not in caplog.text

    assert "[REDACTED]" in captured.err
    assert "[CVE_REDACTED]" in captured.err

    failure_record = next(
        record
        for record in caplog.records
        if record.getMessage()
        == (
            "EPSS synchronization "
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
            "build_epss_synchronization_job",
            side_effect=RuntimeError(
                "invalid EPSS configuration"
            ),
        ),
    ):
        exit_code = main(
            [
                "CVE-2021-44228",
            ]
        )

    captured = capsys.readouterr()

    assert exit_code == 1
    assert captured.out == ""

    assert (
        "invalid EPSS configuration"
        in captured.err
    )