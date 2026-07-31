from __future__ import annotations

from unittest.mock import Mock, patch
from uuid import uuid4

import pytest

from scripts.run_phishtank_ingestion import (
    DEFAULT_SAFE_LIMIT,
    main,
)


@patch(
    "scripts.run_phishtank_ingestion."
    "build_phishtank_ingestion_job"
)
def test_main_uses_safe_defaults(
    build_job: Mock,
    capsys: pytest.CaptureFixture[str],
) -> None:
    source_id = uuid4()
    run_id = uuid4()

    job = Mock()

    job.run.return_value = Mock(
        run_id=run_id,
        records_received=100,
        records_persisted=100,
        records_skipped=0,
        status="completed",
    )

    build_job.return_value = job

    exit_code = main(
        [
            "--source-id",
            str(source_id),
        ]
    )

    build_job.assert_called_once_with(
        source_id=source_id,
        limit=DEFAULT_SAFE_LIMIT,
        force_download=False,
        batch_size=500,
    )

    job.run.assert_called_once_with()

    assert exit_code == 0

    output = capsys.readouterr().out

    assert str(run_id) in output
    assert "persisted=100" in output


@patch(
    "scripts.run_phishtank_ingestion."
    "build_phishtank_ingestion_job"
)
def test_main_forwards_limited_configuration(
    build_job: Mock,
) -> None:
    source_id = uuid4()

    job = Mock()

    job.run.return_value = Mock(
        run_id=uuid4(),
        records_received=25,
        records_persisted=25,
        records_skipped=0,
        status="completed",
    )

    build_job.return_value = job

    exit_code = main(
        [
            "--source-id",
            str(source_id),
            "--limit",
            "25",
            "--batch-size",
            "10",
            "--force-download",
        ]
    )

    build_job.assert_called_once_with(
        source_id=source_id,
        limit=25,
        force_download=True,
        batch_size=10,
    )

    assert exit_code == 0


@patch(
    "scripts.run_phishtank_ingestion."
    "build_phishtank_ingestion_job"
)
def test_main_allows_explicit_full_snapshot(
    build_job: Mock,
) -> None:
    source_id = uuid4()

    job = Mock()

    job.run.return_value = Mock(
        run_id=uuid4(),
        records_received=1_500,
        records_persisted=1_500,
        records_skipped=0,
        status="completed",
    )

    build_job.return_value = job

    exit_code = main(
        [
            "--source-id",
            str(source_id),
            "--full",
        ]
    )

    build_job.assert_called_once_with(
        source_id=source_id,
        limit=None,
        force_download=False,
        batch_size=500,
    )

    assert exit_code == 0


def test_main_rejects_unsafe_limit() -> None:
    with pytest.raises(
        SystemExit,
    ) as exc_info:
        main(
            [
                "--source-id",
                str(uuid4()),
                "--limit",
                "1001",
            ]
        )

    assert exc_info.value.code == 2


def test_main_requires_source_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(
        "PHISHTANK_SOURCE_ID",
        raising=False,
    )

    with pytest.raises(
        SystemExit,
    ) as exc_info:
        main([])

    assert exc_info.value.code == 2