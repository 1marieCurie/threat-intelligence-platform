from __future__ import annotations

import logging
from unittest.mock import Mock, patch
from uuid import uuid4

import pytest

import infrastructure.cli.phishtank_normalization as phishtank_normalization
from infrastructure.adapters.inbound.phishtank_normalization_job import (
    PhishTankNormalizationJobResult,
)


def _build_result(
) -> PhishTankNormalizationJobResult:
    return PhishTankNormalizationJobResult(
        batches=2,
        claimed=5,
        normalized=4,
        already_normalized=0,
        failed=1,
        requeued=0,
        stale_failed=0,
    )


@patch.object(
    phishtank_normalization,
    "configure_logging",
)
@patch.object(
    phishtank_normalization,
    "build_phishtank_normalization_job",
)
def test_main_runs_normalization_job(
    build_job: Mock,
    configure_logging: Mock,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source_id = uuid4()

    job = Mock()
    job.run.return_value = (
        _build_result()
    )

    build_job.return_value = job

    exit_code = (
        phishtank_normalization.main(
            [
                "--source-id",
                str(source_id),
            ]
        )
    )

    assert exit_code == 0

    configure_logging.assert_called_once_with()

    build_job.assert_called_once_with(
        source_id=source_id
    )

    job.run.assert_called_once_with()

    captured = capsys.readouterr()

    assert (
        "PhishTank normalization completed"
        in captured.out
    )
    assert "claimed=5" in captured.out
    assert "normalized=4" in captured.out
    assert "failed=1" in captured.out
    assert captured.err == ""


@patch.object(
    phishtank_normalization,
    "configure_logging",
)
@patch.object(
    phishtank_normalization,
    "build_phishtank_normalization_job",
)
def test_invalid_source_id_returns_one(
    build_job: Mock,
    configure_logging: Mock,
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = (
        phishtank_normalization.main(
            [
                "--source-id",
                "invalid",
            ]
        )
    )

    assert exit_code == 1

    configure_logging.assert_called_once_with()
    build_job.assert_not_called()

    captured = capsys.readouterr()

    assert captured.out == ""
    assert (
        "source-id must be a valid UUID"
        in captured.err
    )


def test_missing_source_id_is_rejected_by_argparse(
) -> None:
    with pytest.raises(
        SystemExit,
    ) as captured:
        phishtank_normalization.main(
            []
        )

    assert captured.value.code == 2


@patch.object(
    phishtank_normalization,
    "configure_logging",
)
@patch.object(
    phishtank_normalization,
    "build_phishtank_normalization_job",
)
def test_safe_configuration_error_is_exposed(
    build_job: Mock,
    configure_logging: Mock,
    capsys: pytest.CaptureFixture[str],
) -> None:
    build_job.side_effect = RuntimeError(
        "PHISHTANK_NORMALIZATION_BATCH_SIZE "
        "must be greater than zero"
    )

    exit_code = (
        phishtank_normalization.main(
            [
                "--source-id",
                str(uuid4()),
            ]
        )
    )

    assert exit_code == 1

    configure_logging.assert_called_once_with()

    captured = capsys.readouterr()

    assert captured.out == ""
    assert (
        "PHISHTANK_NORMALIZATION_BATCH_SIZE "
        "must be greater than zero"
        in captured.err
    )


@patch.object(
    phishtank_normalization,
    "configure_logging",
)
@patch.object(
    phishtank_normalization,
    "build_phishtank_normalization_job",
)
def test_unexpected_error_does_not_expose_url(
    build_job: Mock,
    configure_logging: Mock,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    sensitive_url = (
        "https://user:password@"
        "example.invalid/login?"
        "access_token=secret-value"
    )

    build_job.side_effect = RuntimeError(
        f"database failure: {sensitive_url}"
    )

    with caplog.at_level(
        logging.ERROR
    ):
        exit_code = (
            phishtank_normalization.main(
                [
                    "--source-id",
                    str(uuid4()),
                ]
            )
        )

    assert exit_code == 1

    configure_logging.assert_called_once_with()

    captured = capsys.readouterr()

    assert captured.out == ""

    assert sensitive_url not in captured.err
    assert "password" not in captured.err
    assert "secret-value" not in captured.err

    assert (
        "RuntimeError: normalization "
        "execution failed"
        in captured.err
    )

    assert sensitive_url not in caplog.text
    assert "password" not in caplog.text
    assert "secret-value" not in caplog.text

    failure_record = next(
        record
        for record in caplog.records
        if record.getMessage()
        == (
            "PhishTank normalization "
            "execution failed"
        )
    )

    assert failure_record.exc_info is None

    assert (
        failure_record.__dict__[
            "error_summary"
        ]
        == (
            "RuntimeError: normalization "
            "execution failed"
        )
    )


@patch.object(
    phishtank_normalization,
    "configure_logging",
)
@patch.object(
    phishtank_normalization,
    "build_phishtank_normalization_job",
)
def test_job_failure_returns_one(
    build_job: Mock,
    configure_logging: Mock,
    capsys: pytest.CaptureFixture[str],
) -> None:
    job = Mock()

    job.run.side_effect = RuntimeError(
        "worker failure"
    )

    build_job.return_value = job

    exit_code = (
        phishtank_normalization.main(
            [
                "--source-id",
                str(uuid4()),
            ]
        )
    )

    assert exit_code == 1

    configure_logging.assert_called_once_with()

    build_job.assert_called_once()
    job.run.assert_called_once_with()

    captured = capsys.readouterr()

    assert captured.out == ""

    assert (
        "RuntimeError: normalization "
        "execution failed"
        in captured.err
    )

    assert (
        "worker failure"
        not in captured.err
    )