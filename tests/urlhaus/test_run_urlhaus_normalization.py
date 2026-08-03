from __future__ import annotations

import logging
from unittest.mock import (
    Mock,
    patch,
)
from uuid import uuid4

import pytest

import infrastructure.cli.urlhaus_normalization as urlhaus_cli
from infrastructure.adapters.inbound.urlhaus_normalization_job import (
    URLhausNormalizationJobResult,
)


def _build_result(
) -> URLhausNormalizationJobResult:
    return URLhausNormalizationJobResult(
        batches=2,
        claimed=5,
        normalized=4,
        already_normalized=0,
        failed=1,
        requeued=0,
        stale_failed=0,
    )


@patch.object(
    urlhaus_cli,
    "configure_logging",
)
@patch.object(
    urlhaus_cli,
    "build_urlhaus_normalization_job",
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

    exit_code = urlhaus_cli.main(
        [
            "--source-id",
            str(source_id),
        ]
    )

    assert exit_code == 0

    configure_logging.assert_called_once_with()

    build_job.assert_called_once_with(
        source_id=source_id
    )

    job.run.assert_called_once_with()

    captured = capsys.readouterr()

    assert (
        "URLhaus normalization completed"
        in captured.out
    )

    assert "claimed=5" in captured.out
    assert "normalized=4" in captured.out
    assert "failed=1" in captured.out
    assert captured.err == ""


@patch.object(
    urlhaus_cli,
    "configure_logging",
)
@patch.object(
    urlhaus_cli,
    "build_urlhaus_normalization_job",
)
def test_main_reads_source_id_from_environment(
    build_job: Mock,
    configure_logging: Mock,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_id = uuid4()

    monkeypatch.setenv(
        urlhaus_cli.URLHAUS_SOURCE_ID_ENV,
        str(source_id),
    )

    job = Mock()
    job.run.return_value = (
        _build_result()
    )

    build_job.return_value = job

    exit_code = urlhaus_cli.main(
        []
    )

    assert exit_code == 0

    build_job.assert_called_once_with(
        source_id=source_id
    )


@patch.object(
    urlhaus_cli,
    "configure_logging",
)
@patch.object(
    urlhaus_cli,
    "build_urlhaus_normalization_job",
)
def test_missing_source_id_returns_one(
    build_job: Mock,
    configure_logging: Mock,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.delenv(
        urlhaus_cli.URLHAUS_SOURCE_ID_ENV,
        raising=False,
    )

    exit_code = urlhaus_cli.main(
        []
    )

    assert exit_code == 1
    build_job.assert_not_called()

    captured = capsys.readouterr()

    assert (
        "source-id is required"
        in captured.err
    )


@patch.object(
    urlhaus_cli,
    "configure_logging",
)
@patch.object(
    urlhaus_cli,
    "build_urlhaus_normalization_job",
)
def test_invalid_source_id_returns_one(
    build_job: Mock,
    configure_logging: Mock,
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = urlhaus_cli.main(
        [
            "--source-id",
            "invalid",
        ]
    )

    assert exit_code == 1
    build_job.assert_not_called()

    captured = capsys.readouterr()

    assert (
        "source-id must be a valid UUID"
        in captured.err
    )


@patch.object(
    urlhaus_cli,
    "configure_logging",
)
@patch.object(
    urlhaus_cli,
    "build_urlhaus_normalization_job",
)
def test_safe_configuration_error_is_exposed(
    build_job: Mock,
    configure_logging: Mock,
    capsys: pytest.CaptureFixture[str],
) -> None:
    build_job.side_effect = RuntimeError(
        "URLHAUS_NORMALIZATION_BATCH_SIZE "
        "must not exceed 1000"
    )

    exit_code = urlhaus_cli.main(
        [
            "--source-id",
            str(uuid4()),
        ]
    )

    assert exit_code == 1

    captured = capsys.readouterr()

    assert (
        "URLHAUS_NORMALIZATION_BATCH_SIZE "
        "must not exceed 1000"
        in captured.err
    )


@patch.object(
    urlhaus_cli,
    "configure_logging",
)
@patch.object(
    urlhaus_cli,
    "build_urlhaus_normalization_job",
)
def test_unexpected_error_does_not_expose_ioc(
    build_job: Mock,
    configure_logging: Mock,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    sensitive_url = (
        "https://user:password@"
        "example.invalid/malware?"
        "access_token=secret-value"
    )

    build_job.side_effect = RuntimeError(
        f"database failure: {sensitive_url}"
    )

    with caplog.at_level(
        logging.ERROR
    ):
        exit_code = urlhaus_cli.main(
            [
                "--source-id",
                str(uuid4()),
            ]
        )

    assert exit_code == 1

    captured = capsys.readouterr()

    assert sensitive_url not in captured.err
    assert "password" not in captured.err
    assert "secret-value" not in captured.err

    assert (
        "RuntimeError: normalization "
        "execution failed"
        in captured.err
    )

    assert sensitive_url not in caplog.text
    assert "secret-value" not in caplog.text

    failure_record = next(
        record
        for record in caplog.records
        if record.getMessage()
        == (
            "URLhaus normalization "
            "execution failed"
        )
    )

    assert failure_record.exc_info is None