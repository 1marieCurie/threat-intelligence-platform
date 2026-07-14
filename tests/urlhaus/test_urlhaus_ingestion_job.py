from __future__ import annotations

from typing import Any, Dict, List

import pytest

from domain.collection_result import CollectionResult
from domain.threat import Threat
from infrastructure.adapters.inbound.urlhaus_ingestion_job import (
    URLhausIngestionJob,
)


class FakeURLhausThreatSource:
    """
    Fake application service used to test the ingestion job
    without calling URLhaus or executing real parsing logic.
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


class InvalidFakeSource:
    """
    Fake source returning an invalid result.
    """

    def collect(self) -> Dict[str, Any]:
        return {
            "threats": [],
            "metadata": {},
        }


def test_run_delegates_to_source_collect() -> None:
    expected_result = CollectionResult(
        threats=[],
        metadata={
            "source": "URLHAUS",
            "query_status": "ok",
        },
    )

    source = FakeURLhausThreatSource(
        result=expected_result
    )

    job = URLhausIngestionJob(source)  # type: ignore[arg-type]

    result = job.run()

    assert source.collect_calls == 1
    assert result is expected_result


def test_run_returns_collection_result() -> None:
    threat = Threat(
        id="URLHAUS-12345",
        threat_type="malware_distribution",
        source="URLHAUS",
    )

    expected_result = CollectionResult(
        threats=[threat],
        metadata={
            "source": "URLHAUS",
            "parsed_threats": 1,
        },
    )

    source = FakeURLhausThreatSource(
        result=expected_result
    )

    job = URLhausIngestionJob(source)  # type: ignore[arg-type]

    result = job.run()

    assert isinstance(result, CollectionResult)
    assert len(result.threats) == 1
    assert result.threats[0].id == "URLHAUS-12345"
    assert result.metadata["source"] == "URLHAUS"


def test_run_calls_collect_only_once() -> None:
    expected_result = CollectionResult()

    source = FakeURLhausThreatSource(
        result=expected_result
    )

    job = URLhausIngestionJob(source)  # type: ignore[arg-type]

    job.run()

    assert source.collect_calls == 1


def test_run_preserves_threats_and_metadata() -> None:
    threats: List[Threat] = [
        Threat(
            id="URLHAUS-1",
            threat_type="malware_distribution",
            source="URLHAUS",
        ),
        Threat(
            id="URLHAUS-2",
            threat_type="malware_distribution",
            source="URLHAUS",
        ),
    ]

    metadata = {
        "source": "URLHAUS",
        "query_status": "ok",
        "received_records": 2,
        "parsed_threats": 2,
        "skipped_records": 0,
    }

    expected_result = CollectionResult(
        threats=threats,
        metadata=metadata,
    )

    source = FakeURLhausThreatSource(
        result=expected_result
    )

    job = URLhausIngestionJob(source)  # type: ignore[arg-type]

    result = job.run()

    assert result.threats == threats
    assert result.metadata == metadata


def test_source_property_returns_configured_source() -> None:
    source = FakeURLhausThreatSource(
        result=CollectionResult()
    )

    job = URLhausIngestionJob(source)  # type: ignore[arg-type]

    assert job.source is source


def test_run_rejects_invalid_collect_result() -> None:
    source = InvalidFakeSource()

    job = URLhausIngestionJob(source)  # type: ignore[arg-type]

    with pytest.raises(
        TypeError,
        match="must return a CollectionResult",
    ):
        job.run()