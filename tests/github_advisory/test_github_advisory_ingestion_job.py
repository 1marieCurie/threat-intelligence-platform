from __future__ import annotations

from typing import Any, Dict, List

import pytest

from domain.collection_result import CollectionResult
from domain.threat import Threat
from infrastructure.adapters.inbound.github_advisory_ingestion_job import (
    GitHubAdvisoryIngestionJob,
)


# ============================================================
# Fake source
# ============================================================


class FakeGitHubAdvisoryThreatSource:
    """
    Fake application service used to test the ingestion job
    without performing real GitHub API calls.
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


# ============================================================
# Helpers
# ============================================================


def build_collection_result(
    *,
    threats: List[Threat] | None = None,
    metadata: Dict[str, Any] | None = None,
) -> CollectionResult:
    """
    Build a CollectionResult for ingestion job tests.
    """

    return CollectionResult(
        threats=threats or [],
        metadata=metadata or {},
    )


def build_threat(
    *,
    threat_id: str = "CVE-2021-44228",
) -> Threat:
    """
    Build a minimal normalized GitHub Advisory threat.
    """

    return Threat(
        id=threat_id,
        title="Example GitHub Security Advisory",
        description="Example advisory description.",
        advisory_type="reviewed",
        severity="CRITICAL",
        cvss_score=10.0,
        external_ids={
            "CVE": [threat_id],
            "GHSA": ["GHSA-jfh8-c2jp-5v3q"],
        },
    )


# ============================================================
# Initialization
# ============================================================


def test_job_rejects_none_source() -> None:
    with pytest.raises(
        ValueError,
        match="GitHub Advisory source must not be None",
    ):
        GitHubAdvisoryIngestionJob(
            source=None,  # type: ignore[arg-type]
        )


def test_job_preserves_source_reference() -> None:
    expected_result = build_collection_result()

    source = FakeGitHubAdvisoryThreatSource(
        expected_result
    )

    job = GitHubAdvisoryIngestionJob(
        source=source,  # type: ignore[arg-type]
    )

    assert job.source is source


# ============================================================
# Source orchestration
# ============================================================


def test_job_calls_source_collect_once() -> None:
    expected_result = build_collection_result()

    source = FakeGitHubAdvisoryThreatSource(
        expected_result
    )

    job = GitHubAdvisoryIngestionJob(
        source=source,  # type: ignore[arg-type]
    )

    job.run()

    assert source.collect_calls == 1


def test_job_returns_exact_collection_result() -> None:
    expected_result = build_collection_result(
        threats=[
            build_threat(),
        ],
        metadata={
            "source": "github_advisory",
            "collected_count": 1,
            "parsed_count": 1,
            "skipped_count": 0,
        },
    )

    source = FakeGitHubAdvisoryThreatSource(
        expected_result
    )

    job = GitHubAdvisoryIngestionJob(
        source=source,  # type: ignore[arg-type]
    )

    result = job.run()

    assert result is expected_result
    assert result.threats[0].id == "CVE-2021-44228"
    assert result.metadata["parsed_count"] == 1


def test_job_does_not_modify_threats() -> None:
    threat = build_threat()

    expected_result = build_collection_result(
        threats=[threat],
        metadata={
            "collected_count": 1,
            "parsed_count": 1,
            "skipped_count": 0,
        },
    )

    source = FakeGitHubAdvisoryThreatSource(
        expected_result
    )

    job = GitHubAdvisoryIngestionJob(
        source=source,  # type: ignore[arg-type]
    )

    result = job.run()

    assert result.threats[0] is threat
    assert result.threats[0].cvss_score == 10.0
    assert result.threats[0].severity == "CRITICAL"


def test_job_does_not_modify_metadata() -> None:
    metadata = {
        "source": "github_advisory",
        "collected_count": 2,
        "parsed_count": 1,
        "skipped_count": 1,
    }

    expected_result = build_collection_result(
        threats=[
            build_threat(),
        ],
        metadata=metadata,
    )

    source = FakeGitHubAdvisoryThreatSource(
        expected_result
    )

    job = GitHubAdvisoryIngestionJob(
        source=source,  # type: ignore[arg-type]
    )

    result = job.run()

    assert result.metadata is metadata
    assert result.metadata == {
        "source": "github_advisory",
        "collected_count": 2,
        "parsed_count": 1,
        "skipped_count": 1,
    }


# ============================================================
# Basic summary output
# ============================================================


def test_job_prints_basic_summary(
    capsys: pytest.CaptureFixture[str],
) -> None:
    expected_result = build_collection_result(
        threats=[
            build_threat(
                threat_id="CVE-2021-44228"
            ),
            build_threat(
                threat_id="CVE-2024-4577"
            ),
        ],
        metadata={
            "collected_count": 3,
            "parsed_count": 2,
            "skipped_count": 1,
        },
    )

    source = FakeGitHubAdvisoryThreatSource(
        expected_result
    )

    job = GitHubAdvisoryIngestionJob(
        source=source,  # type: ignore[arg-type]
    )

    job.run()

    captured = capsys.readouterr().out

    assert (
        "[INFO] Starting GitHub Advisory ingestion job..."
        in captured
    )

    assert (
        "[INFO] GitHub Advisory ingestion completed."
        in captured
    )

    assert "[INFO] Collected threats: 2" in captured
    assert "[INFO] Raw advisories: 3" in captured
    assert "[INFO] Parsed advisories: 2" in captured
    assert "[INFO] Skipped advisories: 1" in captured


# ============================================================
# Filter output
# ============================================================


def test_job_prints_configured_filters(
    capsys: pytest.CaptureFixture[str],
) -> None:
    expected_result = build_collection_result(
        metadata={
            "advisory_type": "reviewed",
            "ecosystem": "pip",
            "severity": "high",
            "modified": "2026-07-01..2026-07-13",
            "per_page": 100,
            "max_pages": 3,
        },
    )

    source = FakeGitHubAdvisoryThreatSource(
        expected_result
    )

    job = GitHubAdvisoryIngestionJob(
        source=source,  # type: ignore[arg-type]
    )

    job.run()

    captured = capsys.readouterr().out

    assert "[INFO] Advisory type: reviewed" in captured
    assert "[INFO] Ecosystem filter: pip" in captured
    assert "[INFO] Severity filter: high" in captured

    assert (
        "[INFO] Modified range: "
        "2026-07-01..2026-07-13"
        in captured
    )

    assert "[INFO] Results per page: 100" in captured
    assert "[INFO] Maximum pages: 3" in captured


def test_job_prints_all_ecosystems_when_filter_is_none(
    capsys: pytest.CaptureFixture[str],
) -> None:
    expected_result = build_collection_result(
        metadata={
            "ecosystem": None,
        },
    )

    source = FakeGitHubAdvisoryThreatSource(
        expected_result
    )

    job = GitHubAdvisoryIngestionJob(
        source=source,  # type: ignore[arg-type]
    )

    job.run()

    captured = capsys.readouterr().out

    assert (
        "[INFO] Ecosystem filter: all ecosystems."
        in captured
    )


def test_job_prints_all_severities_when_filter_is_none(
    capsys: pytest.CaptureFixture[str],
) -> None:
    expected_result = build_collection_result(
        metadata={
            "severity": None,
        },
    )

    source = FakeGitHubAdvisoryThreatSource(
        expected_result
    )

    job = GitHubAdvisoryIngestionJob(
        source=source,  # type: ignore[arg-type]
    )

    job.run()

    captured = capsys.readouterr().out

    assert (
        "[INFO] Severity filter: all severities."
        in captured
    )


def test_job_prints_unlimited_pages(
    capsys: pytest.CaptureFixture[str],
) -> None:
    expected_result = build_collection_result(
        metadata={
            "max_pages": None,
        },
    )

    source = FakeGitHubAdvisoryThreatSource(
        expected_result
    )

    job = GitHubAdvisoryIngestionJob(
        source=source,  # type: ignore[arg-type]
    )

    job.run()

    captured = capsys.readouterr().out

    assert (
        "[INFO] Maximum pages: unlimited."
        in captured
    )


# ============================================================
# Technical metadata output
# ============================================================


def test_job_prints_api_version_and_collection_date(
    capsys: pytest.CaptureFixture[str],
) -> None:
    expected_result = build_collection_result(
        metadata={
            "api_version": "2022-11-28",
            "collected_at": (
                "2026-07-13T19:20:00+00:00"
            ),
        },
    )

    source = FakeGitHubAdvisoryThreatSource(
        expected_result
    )

    job = GitHubAdvisoryIngestionJob(
        source=source,  # type: ignore[arg-type]
    )

    job.run()

    captured = capsys.readouterr().out

    assert (
        "[INFO] GitHub API version: 2022-11-28"
        in captured
    )

    assert (
        "[INFO] Collected at: "
        "2026-07-13T19:20:00+00:00"
        in captured
    )


def test_job_omits_modified_range_when_absent(
    capsys: pytest.CaptureFixture[str],
) -> None:
    expected_result = build_collection_result(
        metadata={
            "modified": None,
        },
    )

    source = FakeGitHubAdvisoryThreatSource(
        expected_result
    )

    job = GitHubAdvisoryIngestionJob(
        source=source,  # type: ignore[arg-type]
    )

    job.run()

    captured = capsys.readouterr().out

    assert "Modified range:" not in captured


def test_job_omits_api_version_when_absent(
    capsys: pytest.CaptureFixture[str],
) -> None:
    expected_result = build_collection_result(
        metadata={},
    )

    source = FakeGitHubAdvisoryThreatSource(
        expected_result
    )

    job = GitHubAdvisoryIngestionJob(
        source=source,  # type: ignore[arg-type]
    )

    job.run()

    captured = capsys.readouterr().out

    assert "GitHub API version:" not in captured


# ============================================================
# Missing and empty metadata
# ============================================================


def test_job_handles_missing_count_metadata(
    capsys: pytest.CaptureFixture[str],
) -> None:
    expected_result = build_collection_result(
        threats=[],
        metadata={},
    )

    source = FakeGitHubAdvisoryThreatSource(
        expected_result
    )

    job = GitHubAdvisoryIngestionJob(
        source=source,  # type: ignore[arg-type]
    )

    result = job.run()

    captured = capsys.readouterr().out

    assert result.threats == []

    assert "[INFO] Collected threats: 0" in captured
    assert "[INFO] Raw advisories: 0" in captured
    assert "[INFO] Parsed advisories: 0" in captured
    assert "[INFO] Skipped advisories: 0" in captured


def test_job_uses_threat_count_when_parsed_count_is_missing(
    capsys: pytest.CaptureFixture[str],
) -> None:
    expected_result = build_collection_result(
        threats=[
            build_threat(
                threat_id="CVE-2021-44228"
            ),
            build_threat(
                threat_id="CVE-2024-4577"
            ),
        ],
        metadata={},
    )

    source = FakeGitHubAdvisoryThreatSource(
        expected_result
    )

    job = GitHubAdvisoryIngestionJob(
        source=source,  # type: ignore[arg-type]
    )

    job.run()

    captured = capsys.readouterr().out

    assert "[INFO] Collected threats: 2" in captured
    assert "[INFO] Parsed advisories: 2" in captured


def test_job_handles_empty_collection_result(
    capsys: pytest.CaptureFixture[str],
) -> None:
    expected_result = build_collection_result()

    source = FakeGitHubAdvisoryThreatSource(
        expected_result
    )

    job = GitHubAdvisoryIngestionJob(
        source=source,  # type: ignore[arg-type]
    )

    result = job.run()

    captured = capsys.readouterr().out

    assert result is expected_result
    assert result.threats == []
    assert result.metadata == {}

    assert (
        "[INFO] GitHub Advisory ingestion completed."
        in captured
    )


# ============================================================
# Error propagation
# ============================================================


def test_job_propagates_source_exception() -> None:
    class FailingGitHubAdvisoryThreatSource:
        def collect(self) -> CollectionResult:
            raise RuntimeError(
                "GitHub Advisory collection failed."
            )

    source = FailingGitHubAdvisoryThreatSource()

    job = GitHubAdvisoryIngestionJob(
        source=source,  # type: ignore[arg-type]
    )

    with pytest.raises(
        RuntimeError,
        match="GitHub Advisory collection failed",
    ):
        job.run()