from __future__ import annotations

from typing import Any, Dict, List

import pytest

from domain.collection_result import CollectionResult
from domain.threat import Threat
from infrastructure.adapters.inbound.phishtank_ingestion_job import (
    PhishTankIngestionJob,
)


class FakePhishTankThreatSource:
    """
    Fake PhishTank source used to test the ingestion job
    without network or filesystem access.
    """

    def __init__(
        self,
        result: CollectionResult,
    ) -> None:
        self.result = result
        self.collect_calls = 0

    def collect(self) -> CollectionResult:
        self.collect_calls += 1
        return self.result


def build_collection_result(
    *,
    threats: List[Threat] | None = None,
    metadata: Dict[str, Any] | None = None,
) -> CollectionResult:
    return CollectionResult(
        threats=threats or [],
        metadata=metadata or {},
    )


def test_job_rejects_none_source() -> None:
    with pytest.raises(
        ValueError,
        match="PhishTank source must not be None",
    ):
        PhishTankIngestionJob(
            source=None,  # type: ignore[arg-type]
        )


def test_job_calls_source_collect_once() -> None:
    expected_result = build_collection_result()

    source = FakePhishTankThreatSource(
        expected_result
    )

    job = PhishTankIngestionJob(
        source=source,  # type: ignore[arg-type]
    )

    job.run()

    assert source.collect_calls == 1


def test_job_returns_exact_collection_result() -> None:
    expected_result = build_collection_result(
        threats=[
            Threat(
                id="PHISHTANK-9477391",
                threat_type="phishing",
                source="PHISHTANK",
            )
        ],
        metadata={
            "source": "PHISHTANK",
            "raw_record_count": 1,
            "threat_count": 1,
            "skipped_record_count": 0,
        },
    )

    source = FakePhishTankThreatSource(
        expected_result
    )

    job = PhishTankIngestionJob(
        source=source,  # type: ignore[arg-type]
    )

    result = job.run()

    assert result is expected_result
    assert result.threats[0].id == (
        "PHISHTANK-9477391"
    )


def test_job_prints_basic_summary(
    capsys: pytest.CaptureFixture[str],
) -> None:
    expected_result = build_collection_result(
        threats=[
            Threat(
                id="PHISHTANK-1",
                threat_type="phishing",
                source="PHISHTANK",
            ),
            Threat(
                id="PHISHTANK-2",
                threat_type="phishing",
                source="PHISHTANK",
            ),
        ],
        metadata={
            "raw_record_count": 3,
            "skipped_record_count": 1,
        },
    )

    source = FakePhishTankThreatSource(
        expected_result
    )

    job = PhishTankIngestionJob(
        source=source,  # type: ignore[arg-type]
    )

    job.run()

    captured = capsys.readouterr().out

    assert (
        "[INFO] Starting PhishTank ingestion job..."
        in captured
    )

    assert (
        "[INFO] PhishTank ingestion completed."
        in captured
    )

    assert "[INFO] Collected threats: 2" in captured
    assert "[INFO] Raw records: 3" in captured
    assert "[INFO] Skipped records: 1" in captured


def test_job_prints_downloaded_snapshot_status(
    capsys: pytest.CaptureFixture[str],
) -> None:
    expected_result = build_collection_result(
        metadata={
            "downloaded": True,
            "used_local_snapshot": False,
            "etag": '"etag-123"',
            "last_modified": (
                "Mon, 13 Jul 2026 12:23:00 GMT"
            ),
        }
    )

    source = FakePhishTankThreatSource(
        expected_result
    )

    job = PhishTankIngestionJob(
        source=source,  # type: ignore[arg-type]
    )

    job.run()

    captured = capsys.readouterr().out

    assert (
        "Snapshot status: new snapshot downloaded."
        in captured
    )

    assert 'Snapshot ETag: "etag-123"' in captured

    assert (
        "Last modified: "
        "Mon, 13 Jul 2026 12:23:00 GMT"
        in captured
    )


def test_job_prints_local_snapshot_status(
    capsys: pytest.CaptureFixture[str],
) -> None:
    expected_result = build_collection_result(
        metadata={
            "downloaded": False,
            "used_local_snapshot": True,
        }
    )

    source = FakePhishTankThreatSource(
        expected_result
    )

    job = PhishTankIngestionJob(
        source=source,  # type: ignore[arg-type]
    )

    job.run()

    captured = capsys.readouterr().out

    assert (
        "Snapshot status: local snapshot reused."
        in captured
    )


def test_job_prints_unavailable_snapshot_status(
    capsys: pytest.CaptureFixture[str],
) -> None:
    expected_result = build_collection_result(
        metadata={}
    )

    source = FakePhishTankThreatSource(
        expected_result
    )

    job = PhishTankIngestionJob(
        source=source,  # type: ignore[arg-type]
    )

    job.run()

    captured = capsys.readouterr().out

    assert (
        "Snapshot status: unavailable."
        in captured
    )


def test_job_handles_missing_metadata_counts(
    capsys: pytest.CaptureFixture[str],
) -> None:
    expected_result = build_collection_result(
        threats=[],
        metadata={},
    )

    source = FakePhishTankThreatSource(
        expected_result
    )

    job = PhishTankIngestionJob(
        source=source,  # type: ignore[arg-type]
    )

    result = job.run()

    captured = capsys.readouterr().out

    assert result.threats == []
    assert "[INFO] Collected threats: 0" in captured
    assert "[INFO] Raw records: 0" in captured
    assert "[INFO] Skipped records: 0" in captured