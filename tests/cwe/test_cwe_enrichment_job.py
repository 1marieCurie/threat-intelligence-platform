from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import pytest

from application.services.cwe_enrichment_service import (
    CWEEnrichmentResult,
    CWEEnrichmentService,
)
from domain.cwe_weakness import CWEWeakness
from domain.threat import Threat
from domain.weakness_reference import WeaknessReference
from infrastructure.adapters.inbound.cwe_enrichment_job import (
    CWEEnrichmentJob,
    CWEEnrichmentJobResult,
)


class FakeCWELookupService:
    """
    Deterministic CWE lookup used by job tests.
    """

    def __init__(
        self,
        *,
        result: dict[
            str,
            CWEWeakness,
        ] | None = None,
    ) -> None:
        self.result = dict(
            result or {}
        )

        self.calls: list[
            list[str | None]
        ] = []

    def find_many_by_cwe_ids(
        self,
        cwe_ids: Iterable[str | None],
    ) -> dict[str, CWEWeakness]:
        provided_ids = list(
            cwe_ids
        )

        self.calls.append(
            provided_ids
        )

        return dict(
            self.result
        )


@pytest.fixture
def cwe_79() -> CWEWeakness:
    return CWEWeakness(
        id="CWE-79",
        name="Cross-site Scripting",
        description="Official CWE-79 description.",
    )


@pytest.fixture
def cwe_89() -> CWEWeakness:
    return CWEWeakness(
        id="CWE-89",
        name="SQL Injection",
        description="Official CWE-89 description.",
    )


@pytest.fixture
def lookup(
    cwe_79: CWEWeakness,
    cwe_89: CWEWeakness,
) -> FakeCWELookupService:
    return FakeCWELookupService(
        result={
            "CWE-79": cwe_79,
            "CWE-89": cwe_89,
        }
    )


@pytest.fixture
def service(
    lookup: FakeCWELookupService,
) -> CWEEnrichmentService:
    return CWEEnrichmentService(
        cwe_lookup=lookup,  # type: ignore[arg-type]
    )


@pytest.fixture
def job(
    service: CWEEnrichmentService,
) -> CWEEnrichmentJob:
    return CWEEnrichmentJob(
        service=service
    )


def test_constructor_stores_service(
    service: CWEEnrichmentService,
) -> None:
    job = CWEEnrichmentJob(
        service=service
    )

    assert job.service is service


def test_constructor_rejects_missing_service(
) -> None:
    with pytest.raises(
        ValueError,
        match="service is required",
    ):
        CWEEnrichmentJob(
            service=None,  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "invalid_service",
    [
        "invalid",
        123,
        {},
        [],
    ],
)
def test_constructor_rejects_invalid_service_type(
    invalid_service: Any,
) -> None:
    with pytest.raises(
        TypeError,
        match=(
            "service must be a "
            "CWEEnrichmentService instance"
        ),
    ):
        CWEEnrichmentJob(
            service=invalid_service
        )


def test_job_result_exposes_threats_and_metadata(
) -> None:
    threat = Threat(
        id="CVE-2026-0001"
    )

    enrichment_result = CWEEnrichmentResult(
        threats=[
            threat,
        ],
        metadata={
            "status": "SUCCESS",
        },
    )

    result = CWEEnrichmentJobResult(
        enrichment_result=enrichment_result
    )

    assert result.threats == [
        threat,
    ]

    assert result.metadata == {
        "status": "SUCCESS",
    }

    assert (
        result.enrichment_result
        is enrichment_result
    )


def test_run_enriches_threat_collection(
    job: CWEEnrichmentJob,
    lookup: FakeCWELookupService,
    cwe_79: CWEWeakness,
    cwe_89: CWEWeakness,
) -> None:
    first = Threat(
        id="CVE-2026-1001",
        weakness_references=[
            WeaknessReference(
                source="NVD",
                cwe_id="CWE-79",
                resolution_status="resolved",
            )
        ],
    )

    second = Threat(
        id="CVE-2026-1002",
        weakness_references=[
            WeaknessReference(
                source="GITHUB_ADVISORY",
                cwe_id="CWE-89",
                resolution_status="resolved",
            )
        ],
    )

    result = job.run(
        [
            first,
            second,
        ]
    )

    assert isinstance(
        result,
        CWEEnrichmentJobResult,
    )

    assert result.threats == [
        first,
        second,
    ]

    assert first.official_weaknesses == [
        cwe_79,
    ]

    assert second.official_weaknesses == [
        cwe_89,
    ]

    assert lookup.calls == [
        [
            "CWE-79",
            "CWE-89",
        ]
    ]

    assert result.metadata[
        "repository_queries"
    ] == 1

    assert result.metadata[
        "newly_enriched_threats"
    ] == 2


def test_run_preserves_original_threat_instances(
    job: CWEEnrichmentJob,
) -> None:
    threat = Threat(
        id="CVE-2026-1003",
        weakness_references=[
            WeaknessReference(
                source="NVD",
                cwe_id="CWE-79",
                resolution_status="resolved",
            )
        ],
    )

    result = job.run(
        [
            threat,
        ]
    )

    assert result.threats[0] is threat


def test_run_accepts_generator(
    job: CWEEnrichmentJob,
    cwe_79: CWEWeakness,
) -> None:
    threats = (
        Threat(
            id=f"CVE-2026-{index}",
            weakness_references=[
                WeaknessReference(
                    source="NVD",
                    cwe_id="CWE-79",
                    resolution_status="resolved",
                )
            ],
        )
        for index in range(2)
    )

    result = job.run(
        threats
    )

    assert len(
        result.threats
    ) == 2

    for threat in result.threats:
        assert threat.official_weaknesses == [
            cwe_79,
        ]


def test_run_empty_collection(
    job: CWEEnrichmentJob,
    lookup: FakeCWELookupService,
) -> None:
    result = job.run([])

    assert result.threats == []
    assert lookup.calls == []

    assert result.metadata[
        "total_threats"
    ] == 0

    assert result.metadata[
        "repository_queries"
    ] == 0


def test_run_deduplicates_lookup_across_threats(
    job: CWEEnrichmentJob,
    lookup: FakeCWELookupService,
) -> None:
    first = Threat(
        id="CVE-2026-2001",
        weakness_references=[
            WeaknessReference(
                source="NVD",
                cwe_id="CWE-79",
                resolution_status="resolved",
            )
        ],
    )

    second = Threat(
        id="CVE-2026-2002",
        weakness_references=[
            WeaknessReference(
                source="MITRE",
                cwe_id="CWE-79",
                resolution_status="resolved",
            )
        ],
    )

    result = job.run(
        [
            first,
            second,
        ]
    )

    assert lookup.calls == [
        [
            "CWE-79",
        ]
    ]

    assert result.metadata[
        "repository_queries"
    ] == 1

    assert result.metadata[
        "newly_enriched_threats"
    ] == 2


def test_run_preserves_unresolved_reference(
    job: CWEEnrichmentJob,
    lookup: FakeCWELookupService,
) -> None:
    reference = WeaknessReference(
        source="MITRE",
        cwe_id=None,
        source_description=(
            "Unknown weakness description"
        ),
        resolution_status="unresolved",
    )

    threat = Threat(
        id="CVE-2026-2003",
        weakness_references=[
            reference,
        ],
    )

    result = job.run(
        [
            threat,
        ]
    )

    assert lookup.calls == []

    assert threat.weakness_references == [
        reference,
    ]

    assert threat.official_weaknesses == []

    assert result.metadata[
        "unresolved_references"
    ] == 1


def test_run_single_enriches_one_threat(
    job: CWEEnrichmentJob,
    lookup: FakeCWELookupService,
    cwe_79: CWEWeakness,
) -> None:
    threat = Threat(
        id="CVE-2026-3001",
        weakness_references=[
            WeaknessReference(
                source="NVD",
                cwe_id="CWE-79",
                resolution_status="resolved",
            )
        ],
    )

    result = job.run_single(
        threat
    )

    assert result.threats == [
        threat,
    ]

    assert threat.official_weaknesses == [
        cwe_79,
    ]

    assert lookup.calls == [
        [
            "CWE-79",
        ]
    ]


@pytest.mark.parametrize(
    "invalid_threat",
    [
        None,
        "CVE-2026-0001",
        123,
        {},
        [],
    ],
)
def test_run_single_rejects_invalid_type(
    job: CWEEnrichmentJob,
    invalid_threat: Any,
) -> None:
    with pytest.raises(
        TypeError,
        match="threat must be a Threat instance",
    ):
        job.run_single(
            invalid_threat
        )


@pytest.mark.parametrize(
    "invalid_collection",
    [
        None,
        123,
        7.9,
        "invalid",
        b"invalid",
    ],
)
def test_run_rejects_invalid_collection(
    job: CWEEnrichmentJob,
    invalid_collection: Any,
) -> None:
    with pytest.raises(
        TypeError,
        match=(
            "threats must be an iterable "
            "of Threat objects"
        ),
    ):
        job.run(
            invalid_collection
        )


def test_run_rejects_invalid_collection_element(
    job: CWEEnrichmentJob,
) -> None:
    with pytest.raises(
        TypeError,
        match=(
            "Every threats element must be "
            "a Threat instance"
        ),
    ):
        job.run(
            [
                Threat(
                    id="CVE-2026-4001"
                ),
                None,  # type: ignore[list-item]
            ]
        )


def test_run_handles_missing_cwe(
    job: CWEEnrichmentJob,
    lookup: FakeCWELookupService,
) -> None:
    threat = Threat(
        id="CVE-2026-5001",
        weakness_references=[
            WeaknessReference(
                source="NVD",
                cwe_id="CWE-999999",
                resolution_status="resolved",
            )
        ],
    )

    result = job.run(
        [
            threat,
        ]
    )

    assert lookup.calls == [
        [
            "CWE-999999",
        ]
    ]

    assert threat.official_weaknesses == []

    assert result.metadata[
        "missing_cwe_ids"
    ] == [
        "CWE-999999",
    ]