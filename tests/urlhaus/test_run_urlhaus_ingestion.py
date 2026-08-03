from __future__ import annotations

import os
from dataclasses import dataclass
from unittest.mock import Mock, patch
from uuid import UUID, uuid4

import pytest

from scripts.run_urlhaus_ingestion import (
    DEFAULT_SAFE_LIMIT,
    main,
)


@dataclass(
    frozen=True,
    slots=True,
)
class FakeResult:
    run_id: UUID
    records_received: int = 10
    records_persisted: int = 8
    records_skipped: int = 2
    status: str = "completed"


def test_main_uses_explicit_source_id_and_defaults(
    capsys: pytest.CaptureFixture[str],
) -> None:
    source_id = uuid4()

    job = Mock()
    job.run.return_value = FakeResult(
        run_id=uuid4()
    )

    with patch(
        "scripts.run_urlhaus_ingestion."
        "build_urlhaus_ingestion_job",
        return_value=job,
    ) as build_job:
        exit_code = main(
            [
                "--source-id",
                str(source_id),
            ]
        )

    assert exit_code == 0

    build_job.assert_called_once_with(
        source_id=source_id,
        limit=DEFAULT_SAFE_LIMIT,
        batch_size=500,
    )

    job.run.assert_called_once_with()

    output = capsys.readouterr()

    assert (
        "URLhaus ingestion completed"
        in output.out
    )

    assert output.err == ""


def test_main_reads_source_id_from_environment(
) -> None:
    source_id = uuid4()

    job = Mock()
    job.run.return_value = FakeResult(
        run_id=uuid4()
    )

    with (
        patch.dict(
            os.environ,
            {
                "URLHAUS_SOURCE_ID": (
                    str(source_id)
                ),
            },
            clear=False,
        ),
        patch(
            "scripts.run_urlhaus_ingestion."
            "build_urlhaus_ingestion_job",
            return_value=job,
        ) as build_job,
    ):
        exit_code = main(
            [
                "--limit",
                "25",
                "--batch-size",
                "10",
            ]
        )

    assert exit_code == 0

    build_job.assert_called_once_with(
        source_id=source_id,
        limit=25,
        batch_size=10,
    )


def test_main_max_window_uses_no_limit(
) -> None:
    source_id = uuid4()

    job = Mock()
    job.run.return_value = FakeResult(
        run_id=uuid4()
    )

    with patch(
        "scripts.run_urlhaus_ingestion."
        "build_urlhaus_ingestion_job",
        return_value=job,
    ) as build_job:
        exit_code = main(
            [
                "--source-id",
                str(source_id),
                "--max-window",
            ]
        )

    assert exit_code == 0

    build_job.assert_called_once_with(
        source_id=source_id,
        limit=None,
        batch_size=500,
    )


def test_main_rejects_limit_above_provider_maximum(
) -> None:
    with pytest.raises(
        SystemExit,
    ) as captured_exit:
        main(
            [
                "--source-id",
                str(uuid4()),
                "--limit",
                "1001",
            ]
        )

    assert captured_exit.value.code == 2


def test_main_requires_source_id(
) -> None:
    with patch.dict(
        os.environ,
        {},
        clear=False,
    ):
        os.environ.pop(
            "URLHAUS_SOURCE_ID",
            None,
        )

        with pytest.raises(
            SystemExit,
        ) as captured_exit:
            main([])

    assert captured_exit.value.code == 2


def test_main_rejects_invalid_environment_source_id(
) -> None:
    with patch.dict(
        os.environ,
        {
            "URLHAUS_SOURCE_ID": (
                "invalid-uuid"
            ),
        },
        clear=False,
    ):
        with pytest.raises(
            SystemExit,
        ) as captured_exit:
            main([])

    assert captured_exit.value.code == 2


def test_main_returns_generic_error_without_leak(
    capsys: pytest.CaptureFixture[str],
) -> None:
    sensitive_error = RuntimeError(
        "database failure for "
        "http://user:password@"
        "malicious.example/"
        "?access_token=private-token"
    )

    job = Mock()
    job.run.side_effect = (
        sensitive_error
    )

    with patch(
        "scripts.run_urlhaus_ingestion."
        "build_urlhaus_ingestion_job",
        return_value=job,
    ):
        exit_code = main(
            [
                "--source-id",
                str(uuid4()),
            ]
        )

    assert exit_code == 1

    output = capsys.readouterr()

    assert output.out == ""

    assert output.err == (
        "URLhaus ingestion failed: "
        "unexpected error.\n"
    )

    assert (
        "private-token"
        not in output.err
    )

    assert (
        "password"
        not in output.err
    )

    assert (
        "malicious.example"
        not in output.err
    )


def test_main_handles_bootstrap_failure_safely(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with patch(
        "scripts.run_urlhaus_ingestion."
        "build_urlhaus_ingestion_job",
        side_effect=RuntimeError(
            "URLHAUS_AUTH_KEY=private-key"
        ),
    ):
        exit_code = main(
            [
                "--source-id",
                str(uuid4()),
            ]
        )

    assert exit_code == 1

    output = capsys.readouterr()

    assert (
        output.err
        == (
            "URLhaus ingestion failed: "
            "unexpected error.\n"
        )
    )

    assert (
        "private-key"
        not in output.err
    )