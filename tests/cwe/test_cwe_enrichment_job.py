from __future__ import annotations

from typing import Any

import pytest

from application.ports.outbound.cwe_repository import (
    CWERepository,
)
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
from infrastructure.adapters.outbound.cwe_connector import (
    CWEConnector,
)


# ============================================================
# Fake repository
# ============================================================


class FakeCWERepository(CWERepository):
    """
    In-memory CWE repository used by unit tests.
    """

    def __init__(
        self,
        entries: dict[str, CWEWeakness] | None = None,
    ) -> None:
        self.entries = dict(
            entries or {}
        )

        self.calls: list[str] = []

    def find_by_id(
        self,
        cwe_id: str,
    ) -> CWEWeakness | None:
        self.calls.append(
            cwe_id
        )

        return self.entries.get(
            cwe_id
        )


# ============================================================
# Live repository for integration tests
# ============================================================


class LiveCWERepository(CWERepository):
    """
    Minimal live repository used only by integration tests.

    It retrieves one CWE entry through the real MITRE API and
    converts it into a CWEWeakness domain object.
    """

    def __init__(
        self,
        connector: CWEConnector | None = None,
    ) -> None:
        self.connector = (
            connector
            or CWEConnector()
        )

        self.calls: list[str] = []

    def find_by_id(
        self,
        cwe_id: str,
    ) -> CWEWeakness | None:
        self.calls.append(
            cwe_id
        )

        payload = self.connector.fetch_weakness(
            cwe_id
        )

        weaknesses = payload.get(
            "Weaknesses",
            [],
        )

        if not weaknesses:
            return None

        raw = weaknesses[0]

        if not isinstance(raw, dict):
            return None

        raw_id = raw.get("ID")

        if raw_id is None:
            return None

        return CWEWeakness(
            id=f"CWE-{raw_id}",
            name=str(
                raw.get("Name")
                or ""
            ),
            description=str(
                raw.get("Description")
                or ""
            ),
            abstraction=_optional_string(
                raw.get("Abstraction")
            ),
            structure=_optional_string(
                raw.get("Structure")
            ),
            status=_optional_string(
                raw.get("Status")
            ),
            extended_description=_optional_string(
                raw.get("ExtendedDescription")
            ),
            likelihood_of_exploit=_optional_string(
                raw.get("LikelihoodOfExploit")
            ),
            raw=raw,
        )


def _optional_string(
    value: Any,
) -> str | None:
    """
    Convert a possible API value to an optional normalized string.
    """

    if not isinstance(value, str):
        return None

    normalized = value.strip()

    return normalized or None


# ============================================================
# Fixtures
# ============================================================


@pytest.fixture
def cwe_79() -> CWEWeakness:
    return CWEWeakness(
        id="CWE-79",
        name=(
            "Improper Neutralization of Input "
            "During Web Page Generation "
            "('Cross-site Scripting')"
        ),
        description=(
            "The product does not correctly neutralize "
            "user-controlled input in generated web content."
        ),
        abstraction="Base",
        structure="Simple",
        status="Stable",
        alternate_terms=(
            "XSS",
        ),
        catalog_version="4.20",
        catalog_date="2026-04-30",
    )


@pytest.fixture
def cwe_89() -> CWEWeakness:
    return CWEWeakness(
        id="CWE-89",
        name=(
            "Improper Neutralization of Special Elements "
            "used in an SQL Command"
        ),
        description=(
            "The product constructs an SQL command using "
            "externally influenced input."
        ),
        abstraction="Base",
        structure="Simple",
        status="Stable",
        alternate_terms=(
            "SQL Injection",
        ),
        catalog_version="4.20",
        catalog_date="2026-04-30",
    )


@pytest.fixture
def repository(
    cwe_79: CWEWeakness,
    cwe_89: CWEWeakness,
) -> FakeCWERepository:
    return FakeCWERepository(
        entries={
            "CWE-79": cwe_79,
            "CWE-89": cwe_89,
        }
    )


@pytest.fixture
def service(
    repository: FakeCWERepository,
) -> CWEEnrichmentService:
    return CWEEnrichmentService(
        repository=repository
    )


@pytest.fixture
def job(
    service: CWEEnrichmentService,
) -> CWEEnrichmentJob:
    return CWEEnrichmentJob(
        service=service
    )


# ============================================================
# Constructor tests
# ============================================================


def test_unit_constructor_stores_service(
    service: CWEEnrichmentService,
) -> None:
    job = CWEEnrichmentJob(
        service=service
    )

    assert job.service is service


def test_unit_constructor_rejects_missing_service(
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
def test_unit_constructor_rejects_invalid_service_type(
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


# ============================================================
# Job result tests
# ============================================================


def test_unit_job_result_exposes_threats_and_metadata(
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


# ============================================================
# Multiple Threat execution tests
# ============================================================


def test_unit_run_enriches_threat_collection(
    job: CWEEnrichmentJob,
    repository: FakeCWERepository,
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

    assert repository.calls == [
        "CWE-79",
        "CWE-89",
    ]

    assert result.metadata[
        "total_threats"
    ] == 2

    assert result.metadata[
        "newly_enriched_threats"
    ] == 2

    assert result.metadata[
        "newly_added_official_weaknesses"
    ] == 2


def test_unit_run_preserves_original_threat_instances(
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


def test_unit_run_accepts_generator(
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


def test_unit_run_empty_collection(
    job: CWEEnrichmentJob,
    repository: FakeCWERepository,
) -> None:
    result = job.run([])

    assert result.threats == []
    assert repository.calls == []

    assert result.metadata[
        "total_threats"
    ] == 0

    assert result.metadata[
        "repository_queries"
    ] == 0


def test_unit_run_uses_service_cache_across_threats(
    job: CWEEnrichmentJob,
    repository: FakeCWERepository,
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

    assert repository.calls == [
        "CWE-79",
    ]

    assert result.metadata[
        "repository_queries"
    ] == 1

    assert result.metadata[
        "newly_enriched_threats"
    ] == 2


def test_unit_run_preserves_unresolved_reference(
    job: CWEEnrichmentJob,
    repository: FakeCWERepository,
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

    assert repository.calls == []
    assert threat.weakness_references == [
        reference,
    ]

    assert threat.official_weaknesses == []

    assert result.metadata[
        "unresolved_references"
    ] == 1

    assert result.metadata[
        "skipped_references"
    ] == 1


# ============================================================
# Single Threat execution tests
# ============================================================


def test_unit_run_single_enriches_one_threat(
    job: CWEEnrichmentJob,
    repository: FakeCWERepository,
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

    assert isinstance(
        result,
        CWEEnrichmentJobResult,
    )

    assert result.threats == [
        threat,
    ]

    assert threat.official_weaknesses == [
        cwe_79,
    ]

    assert repository.calls == [
        "CWE-79",
    ]

    assert result.metadata[
        "total_threats"
    ] == 1


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
def test_unit_run_single_rejects_invalid_type(
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


# ============================================================
# Collection validation tests
# ============================================================


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
def test_unit_run_rejects_invalid_collection(
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


def test_unit_run_rejects_invalid_collection_element(
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


# ============================================================
# Missing CWE tests
# ============================================================


def test_unit_run_handles_missing_cwe(
    job: CWEEnrichmentJob,
    repository: FakeCWERepository,
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

    assert repository.calls == [
        "CWE-999999",
    ]

    assert threat.official_weaknesses == []

    assert result.metadata[
        "missing_references"
    ] == 1

    assert result.metadata[
        "missing_unique_cwe_ids"
    ] == 1

    assert result.metadata[
        "missing_cwe_ids"
    ] == [
        "CWE-999999",
    ]


# ============================================================
# Integration tests: job + service + real CWE API
# ============================================================


@pytest.mark.integration
def test_integration_run_single_with_live_cwe_api(
) -> None:
    repository = LiveCWERepository()

    service = CWEEnrichmentService(
        repository=repository
    )

    job = CWEEnrichmentJob(
        service=service
    )

    threat = Threat(
        id="CVE-TEST-JOB-CWE-79",
        weakness_references=[
            WeaknessReference(
                source="NVD",
                cwe_id="CWE-79",
                source_description=(
                    "Cross-site Scripting"
                ),
                resolution_status="resolved",
                resolution_method="explicit_id",
            )
        ],
    )

    result = job.run_single(
        threat
    )

    print(
        "\n========== CWE ENRICHMENT JOB =========="
    )

    print(
        f"Threat ID       : {threat.id}"
    )

    print(
        f"Reference IDs   : {threat.weakness_ids}"
    )

    print(
        "Official CWEs   : "
        f"{len(threat.official_weaknesses)}"
    )

    for weakness in threat.official_weaknesses:
        print(
            f"{weakness.id}: {weakness.name}"
        )

    print(
        "\n========== JOB METADATA =========="
    )

    for key, value in result.metadata.items():
        print(
            f"{key:<35}: {value}"
        )

    assert repository.calls == [
        "CWE-79",
    ]

    assert result.threats == [
        threat,
    ]

    assert len(
        threat.official_weaknesses
    ) == 1

    weakness = threat.official_weaknesses[0]

    assert weakness.id == "CWE-79"
    assert weakness.name
    assert weakness.description
    assert weakness.raw

    assert result.metadata[
        "total_threats"
    ] == 1

    assert result.metadata[
        "newly_enriched_threats"
    ] == 1

    assert result.metadata[
        "repository_queries"
    ] == 1


@pytest.mark.integration
def test_integration_run_multiple_with_live_cwe_api(
) -> None:
    repository = LiveCWERepository()

    service = CWEEnrichmentService(
        repository=repository
    )

    job = CWEEnrichmentJob(
        service=service
    )

    threats = [
        Threat(
            id="CVE-TEST-JOB-CWE-79-A",
            weakness_references=[
                WeaknessReference(
                    source="NVD",
                    cwe_id="CWE-79",
                    resolution_status="resolved",
                )
            ],
        ),
        Threat(
            id="CVE-TEST-JOB-CWE-79-B",
            weakness_references=[
                WeaknessReference(
                    source="MITRE",
                    cwe_id="CWE-79",
                    resolution_status="resolved",
                )
            ],
        ),
        Threat(
            id="CVE-TEST-JOB-CWE-89",
            weakness_references=[
                WeaknessReference(
                    source="GITHUB_ADVISORY",
                    cwe_id="CWE-89",
                    resolution_status="resolved",
                )
            ],
        ),
    ]

    result = job.run(
        threats
    )

    print(
        "\n========== MULTIPLE CWE JOB =========="
    )

    for threat in result.threats:
        weakness_ids = [
            weakness.id
            for weakness
            in threat.official_weaknesses
        ]

        print(
            f"{threat.id}: {weakness_ids}"
        )

    print(
        "\n========== JOB METADATA =========="
    )

    for key, value in result.metadata.items():
        print(
            f"{key:<35}: {value}"
        )

    assert repository.calls == [
        "CWE-79",
        "CWE-89",
    ]

    assert [
        weakness.id
        for weakness
        in threats[0].official_weaknesses
    ] == [
        "CWE-79",
    ]

    assert [
        weakness.id
        for weakness
        in threats[1].official_weaknesses
    ] == [
        "CWE-79",
    ]

    assert [
        weakness.id
        for weakness
        in threats[2].official_weaknesses
    ] == [
        "CWE-89",
    ]

    assert result.metadata[
        "total_threats"
    ] == 3

    assert result.metadata[
        "requested_unique_cwe_ids"
    ] == 2

    assert result.metadata[
        "found_unique_cwe_ids"
    ] == 2

    assert result.metadata[
        "repository_queries"
    ] == 2

    assert result.metadata[
        "newly_enriched_threats"
    ] == 3