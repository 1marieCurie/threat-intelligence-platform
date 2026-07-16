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
from domain.threat_category import ThreatCategory
from domain.weakness_reference import WeaknessReference
from infrastructure.adapters.outbound.cwe_connector import (
    CWEConnector,
)


# ============================================================
# Fake repository
# ============================================================


class FakeCWERepository(CWERepository):
    """
    In-memory repository used by the unit tests.

    It records every requested identifier so that caching and
    deduplication behavior can be verified.
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


class InvalidReturnCWERepository(CWERepository):
    """
    Repository returning an invalid object.

    This verifies that the service protects its domain boundary.
    """

    def find_by_id(
        self,
        cwe_id: str,
    ) -> CWEWeakness | None:
        return {  # type: ignore[return-value]
            "id": cwe_id,
        }


# ============================================================
# Live integration repository
# ============================================================


class LiveCWERepository(CWERepository):
    """
    Minimal repository adapter used only by integration tests.

    It retrieves one entry from the real MITRE CWE API and maps
    the raw response to CWEWeakness.

    This adapter is intentionally local to the test file. The real
    persistent repository will be tested separately.
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
            catalog_version=None,
            catalog_date=None,
            raw=raw,
        )


def _optional_string(
    value: Any,
) -> str | None:
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
        likelihood_of_exploit="High",
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
def cwe_502() -> CWEWeakness:
    return CWEWeakness(
        id="CWE-502",
        name="Deserialization of Untrusted Data",
        description=(
            "The application deserializes untrusted data "
            "without sufficient validation."
        ),
        abstraction="Base",
        structure="Simple",
        status="Stable",
        catalog_version="4.20",
        catalog_date="2026-04-30",
    )


@pytest.fixture
def repository(
    cwe_79: CWEWeakness,
    cwe_89: CWEWeakness,
    cwe_502: CWEWeakness,
) -> FakeCWERepository:
    return FakeCWERepository(
        entries={
            "CWE-79": cwe_79,
            "CWE-89": cwe_89,
            "CWE-502": cwe_502,
        }
    )


@pytest.fixture
def service(
    repository: FakeCWERepository,
) -> CWEEnrichmentService:
    return CWEEnrichmentService(
        repository=repository
    )


# ============================================================
# Constructor tests
# ============================================================


def test_unit_constructor_stores_repository(
    repository: FakeCWERepository,
) -> None:
    service = CWEEnrichmentService(
        repository=repository
    )

    assert service.repository is repository


def test_unit_constructor_rejects_missing_repository(
) -> None:
    with pytest.raises(
        ValueError,
        match="repository is required",
    ):
        CWEEnrichmentService(
            repository=None,  # type: ignore[arg-type]
        )


# ============================================================
# Single Threat enrichment tests
# ============================================================


def test_unit_enrich_single_threat(
    service: CWEEnrichmentService,
    repository: FakeCWERepository,
    cwe_79: CWEWeakness,
) -> None:
    threat = Threat(
        id="CVE-2026-0001",
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

    result = service.enrich_threat(
        threat
    )

    assert isinstance(
        result,
        CWEEnrichmentResult,
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

    assert result.metadata[
        "newly_enriched_threats"
    ] == 1

    assert result.metadata[
        "newly_added_official_weaknesses"
    ] == 1


def test_unit_enrich_threat_preserves_source_reference(
    service: CWEEnrichmentService,
) -> None:
    reference = WeaknessReference(
        source="GITHUB_ADVISORY",
        cwe_id="CWE-79",
        source_description="XSS",
        origin="github_advisory",
        resolution_status="resolved",
        resolution_method="explicit_id",
    )

    threat = Threat(
        id="CVE-2026-0002",
        weakness_references=[
            reference,
        ],
    )

    service.enrich_threat(
        threat
    )

    assert threat.weakness_references == [
        reference,
    ]

    assert (
        threat.weakness_references[0]
        is reference
    )


def test_unit_enrich_threat_normalizes_identifier(
    service: CWEEnrichmentService,
    repository: FakeCWERepository,
    cwe_79: CWEWeakness,
) -> None:
    threat = Threat(
        id="CVE-2026-0003",
        weakness_references=[
            WeaknessReference(
                source="MITRE",
                cwe_id="cwe-00079",
                resolution_status="resolved",
            )
        ],
    )

    service.enrich_threat(
        threat
    )

    assert repository.calls == [
        "CWE-79",
    ]

    assert threat.official_weaknesses == [
        cwe_79,
    ]


# ============================================================
# Resolution status tests
# ============================================================


@pytest.mark.parametrize(
    (
        "status",
        "metadata_key",
    ),
    [
        (
            "unresolved",
            "unresolved_references",
        ),
        (
            "placeholder",
            "placeholder_references",
        ),
        (
            "invalid",
            "invalid_references",
        ),
    ],
)
def test_unit_non_resolvable_reference_is_skipped(
    service: CWEEnrichmentService,
    repository: FakeCWERepository,
    status: str,
    metadata_key: str,
) -> None:
    threat = Threat(
        id=f"CVE-2026-{status}",
        weakness_references=[
            WeaknessReference(
                source="NVD",
                cwe_id="CWE-79",
                resolution_status=status,
            )
        ],
    )

    result = service.enrich_threat(
        threat
    )

    assert threat.official_weaknesses == []
    assert repository.calls == []

    assert result.metadata[
        metadata_key
    ] == 1

    assert result.metadata[
        "skipped_references"
    ] == 1


def test_unit_resolved_reference_without_id_is_invalid(
    service: CWEEnrichmentService,
    repository: FakeCWERepository,
) -> None:
    threat = Threat(
        id="CVE-2026-0004",
        weakness_references=[
            WeaknessReference(
                source="MITRE",
                cwe_id=None,
                source_description="Unknown weakness",
                resolution_status="resolved",
            )
        ],
    )

    result = service.enrich_threat(
        threat
    )

    assert repository.calls == []
    assert threat.official_weaknesses == []

    assert result.metadata[
        "invalid_references"
    ] == 1

    assert result.metadata[
        "skipped_references"
    ] == 1


def test_unit_unknown_resolution_status_is_skipped(
    service: CWEEnrichmentService,
    repository: FakeCWERepository,
) -> None:
    threat = Threat(
        id="CVE-2026-0005",
        weakness_references=[
            WeaknessReference(
                source="NVD",
                cwe_id="CWE-79",
                resolution_status="unknown_status",
            )
        ],
    )

    result = service.enrich_threat(
        threat
    )

    assert repository.calls == []
    assert threat.official_weaknesses == []

    assert result.metadata[
        "skipped_references"
    ] == 1


# ============================================================
# Deduplication tests
# ============================================================


def test_unit_duplicate_source_references_create_one_official_link(
    service: CWEEnrichmentService,
    repository: FakeCWERepository,
    cwe_502: CWEWeakness,
) -> None:
    threat = Threat(
        id="CVE-2021-44228",
        weakness_references=[
            WeaknessReference(
                source="NVD",
                cwe_id="CWE-502",
                resolution_status="resolved",
            ),
            WeaknessReference(
                source="MITRE",
                cwe_id="CWE-502",
                resolution_status="resolved",
            ),
            WeaknessReference(
                source="GITHUB_ADVISORY",
                cwe_id="CWE-502",
                resolution_status="resolved",
            ),
        ],
    )

    result = service.enrich_threat(
        threat
    )

    assert len(
        threat.weakness_references
    ) == 3

    assert threat.official_weaknesses == [
        cwe_502,
    ]

    assert repository.calls == [
        "CWE-502",
    ]

    assert result.metadata[
        "resolved_references"
    ] == 3

    assert result.metadata[
        "newly_added_official_weaknesses"
    ] == 1

    assert result.metadata[
        "duplicate_weakness_links"
    ] == 2


def test_unit_repository_cache_is_shared_between_threats(
    service: CWEEnrichmentService,
    repository: FakeCWERepository,
    cwe_79: CWEWeakness,
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
                source="MITRE",
                cwe_id="CWE-79",
                resolution_status="resolved",
            )
        ],
    )

    result = service.enrich_threats(
        [
            first,
            second,
        ]
    )

    assert repository.calls == [
        "CWE-79",
    ]

    assert first.official_weaknesses == [
        cwe_79,
    ]

    assert second.official_weaknesses == [
        cwe_79,
    ]

    assert result.metadata[
        "repository_queries"
    ] == 1

    assert result.metadata[
        "newly_enriched_threats"
    ] == 2


def test_unit_preserves_existing_official_weakness(
    service: CWEEnrichmentService,
    repository: FakeCWERepository,
    cwe_79: CWEWeakness,
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
        official_weaknesses=[
            cwe_79,
        ],
    )

    result = service.enrich_threat(
        threat
    )

    assert threat.official_weaknesses == [
        cwe_79,
    ]

    assert repository.calls == [
        "CWE-79",
    ]

    assert result.metadata[
        "newly_added_official_weaknesses"
    ] == 0

    assert result.metadata[
        "duplicate_weakness_links"
    ] == 1

    assert result.metadata[
        "already_enriched_threats"
    ] == 1


def test_unit_deduplicates_existing_official_weaknesses(
    service: CWEEnrichmentService,
    cwe_79: CWEWeakness,
) -> None:
    duplicate = CWEWeakness(
        id="cwe-00079",
        name=cwe_79.name,
        description=cwe_79.description,
    )

    threat = Threat(
        id="CVE-2026-1004",
        official_weaknesses=[
            cwe_79,
            duplicate,
        ],
    )

    service.enrich_threat(
        threat
    )

    assert threat.official_weaknesses == [
        cwe_79,
    ]


# ============================================================
# Missing catalog entries
# ============================================================


def test_unit_missing_cwe_does_not_stop_enrichment(
    service: CWEEnrichmentService,
    repository: FakeCWERepository,
) -> None:
    threat = Threat(
        id="CVE-2026-2001",
        weakness_references=[
            WeaknessReference(
                source="NVD",
                cwe_id="CWE-999999",
                resolution_status="resolved",
            ),
            WeaknessReference(
                source="NVD",
                cwe_id="CWE-79",
                resolution_status="resolved",
            ),
        ],
    )

    result = service.enrich_threat(
        threat
    )

    assert [
        weakness.id
        for weakness in threat.official_weaknesses
    ] == [
        "CWE-79",
    ]

    assert repository.calls == [
        "CWE-999999",
        "CWE-79",
    ]

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

    assert result.missing_cwe_ids() == [
        "CWE-999999",
    ]


def test_unit_missing_cwe_is_cached(
    service: CWEEnrichmentService,
    repository: FakeCWERepository,
) -> None:
    threats = [
        Threat(
            id="CVE-2026-2002",
            weakness_references=[
                WeaknessReference(
                    source="NVD",
                    cwe_id="CWE-999999",
                    resolution_status="resolved",
                )
            ],
        ),
        Threat(
            id="CVE-2026-2003",
            weakness_references=[
                WeaknessReference(
                    source="MITRE",
                    cwe_id="CWE-999999",
                    resolution_status="resolved",
                )
            ],
        ),
    ]

    result = service.enrich_threats(
        threats
    )

    assert repository.calls == [
        "CWE-999999",
    ]

    assert result.metadata[
        "missing_references"
    ] == 2

    assert result.metadata[
        "missing_unique_cwe_ids"
    ] == 1

    assert result.metadata[
        "repository_queries"
    ] == 1


# ============================================================
# Several CWE entries
# ============================================================


def test_unit_enrich_threat_with_multiple_cwes(
    service: CWEEnrichmentService,
    repository: FakeCWERepository,
) -> None:
    threat = Threat(
        id="CVE-2026-3001",
        weakness_references=[
            WeaknessReference(
                source="NVD",
                cwe_id="CWE-79",
                resolution_status="resolved",
            ),
            WeaknessReference(
                source="GITHUB_ADVISORY",
                cwe_id="CWE-89",
                resolution_status="resolved",
            ),
        ],
    )

    result = service.enrich_threat(
        threat
    )

    assert [
        weakness.id
        for weakness in threat.official_weaknesses
    ] == [
        "CWE-79",
        "CWE-89",
    ]

    assert repository.calls == [
        "CWE-79",
        "CWE-89",
    ]

    assert result.metadata[
        "requested_unique_cwe_ids"
    ] == 2

    assert result.metadata[
        "found_unique_cwe_ids"
    ] == 2

    assert result.metadata[
        "newly_added_official_weaknesses"
    ] == 2


# ============================================================
# Result helper tests
# ============================================================


def test_unit_result_enriched_threats(
    service: CWEEnrichmentService,
) -> None:
    enriched = Threat(
        id="CVE-2026-4001",
        weakness_references=[
            WeaknessReference(
                source="NVD",
                cwe_id="CWE-79",
                resolution_status="resolved",
            )
        ],
    )

    not_enriched = Threat(
        id="CVE-2026-4002",
        weakness_references=[
            WeaknessReference(
                source="NVD",
                cwe_id=None,
                resolution_status="unresolved",
            )
        ],
    )

    result = service.enrich_threats(
        [
            enriched,
            not_enriched,
        ]
    )

    assert result.enriched_threats() == [
        enriched,
    ]


def test_unit_empty_threat_collection(
    service: CWEEnrichmentService,
    repository: FakeCWERepository,
) -> None:
    result = service.enrich_threats([])

    assert result.threats == []
    assert repository.calls == []

    assert result.metadata[
        "total_threats"
    ] == 0

    assert result.metadata[
        "repository_queries"
    ] == 0

    assert result.enriched_threats() == []
    assert result.missing_cwe_ids() == []


# ============================================================
# Invalid input tests
# ============================================================


@pytest.mark.parametrize(
    "invalid_threat",
    [
        None,
        "CVE-2026-0001",
        {},
        123,
    ],
)
def test_unit_enrich_threat_rejects_invalid_type(
    service: CWEEnrichmentService,
    invalid_threat: Any,
) -> None:
    with pytest.raises(
        TypeError,
        match="threat must be a Threat instance",
    ):
        service.enrich_threat(
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
def test_unit_enrich_threats_rejects_invalid_collection(
    service: CWEEnrichmentService,
    invalid_collection: Any,
) -> None:
    with pytest.raises(
        TypeError,
        match=(
            "threats must be an iterable "
            "of Threat objects"
        ),
    ):
        service.enrich_threats(
            invalid_collection
        )


def test_unit_enrich_threats_rejects_invalid_element(
    service: CWEEnrichmentService,
) -> None:
    with pytest.raises(
        TypeError,
        match=(
            "Every threats element must be "
            "a Threat instance"
        ),
    ):
        service.enrich_threats(
            [
                Threat(
                    id="CVE-2026-5001"
                ),
                None,  # type: ignore[list-item]
            ]
        )


def test_unit_rejects_invalid_repository_return_type(
) -> None:
    service = CWEEnrichmentService(
        repository=InvalidReturnCWERepository()
    )

    threat = Threat(
        id="CVE-2026-5002",
        weakness_references=[
            WeaknessReference(
                source="NVD",
                cwe_id="CWE-79",
                resolution_status="resolved",
            )
        ],
    )

    with pytest.raises(
        TypeError,
        match=(
            "CWERepository.find_by_id\\(\\) "
            "must return CWEWeakness or None"
        ),
    ):
        service.enrich_threat(
            threat
        )


# ============================================================
# Identifier helper tests
# ============================================================


@pytest.mark.parametrize(
    (
        "raw_value",
        "expected",
    ),
    [
        (
            "CWE-79",
            "CWE-79",
        ),
        (
            "cwe-79",
            "CWE-79",
        ),
        (
            "79",
            "CWE-79",
        ),
        (
            79,
            "CWE-79",
        ),
        (
            "00079",
            "CWE-79",
        ),
        (
            "CWE-00079",
            "CWE-79",
        ),
        (
            " CWE-502 ",
            "CWE-502",
        ),
    ],
)
def test_unit_normalize_cwe_id(
    raw_value: Any,
    expected: str,
) -> None:
    assert (
        CWEEnrichmentService._normalize_cwe_id(
            raw_value
        )
        == expected
    )


@pytest.mark.parametrize(
    "invalid_value",
    [
        None,
        "",
        " ",
        "CWE-",
        "CWE-ABC",
        "ABC-79",
        "CWE-0",
        "00000",
        0,
        -1,
        True,
        False,
        7.9,
        [],
        {},
    ],
)
def test_unit_normalize_cwe_id_rejects_invalid_value(
    invalid_value: Any,
) -> None:
    assert (
        CWEEnrichmentService._normalize_cwe_id(
            invalid_value
        )
        is None
    )


# ============================================================
# Integration tests: service + real MITRE CWE API
# ============================================================


@pytest.mark.integration
def test_integration_enrich_single_threat_with_live_cwe(
) -> None:
    repository = LiveCWERepository()

    service = CWEEnrichmentService(
        repository=repository
    )

    threat = Threat(
        id="CVE-TEST-CWE-79",
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

    result = service.enrich_threat(
        threat
    )

    print(
        "\n========== CWE ENRICHMENT =========="
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
        "\n========== METADATA =========="
    )

    for key, value in result.metadata.items():
        print(
            f"{key:<35}: {value}"
        )

    assert repository.calls == [
        "CWE-79",
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
        "newly_enriched_threats"
    ] == 1

    assert result.metadata[
        "found_unique_cwe_ids"
    ] == 1


@pytest.mark.integration
def test_integration_enrich_multiple_threats_with_live_cwe(
) -> None:
    repository = LiveCWERepository()

    service = CWEEnrichmentService(
        repository=repository
    )

    threats = [
        Threat(
            id="CVE-TEST-CWE-79-A",
            weakness_references=[
                WeaknessReference(
                    source="NVD",
                    cwe_id="CWE-79",
                    resolution_status="resolved",
                )
            ],
        ),
        Threat(
            id="CVE-TEST-CWE-79-B",
            weakness_references=[
                WeaknessReference(
                    source="MITRE",
                    cwe_id="CWE-79",
                    resolution_status="resolved",
                )
            ],
        ),
        Threat(
            id="CVE-TEST-CWE-89",
            weakness_references=[
                WeaknessReference(
                    source="GITHUB_ADVISORY",
                    cwe_id="CWE-89",
                    resolution_status="resolved",
                )
            ],
        ),
    ]

    result = service.enrich_threats(
        threats
    )

    print(
        "\n========== MULTIPLE CWE ENRICHMENT =========="
    )

    for threat in threats:
        ids = [
            weakness.id
            for weakness in threat.official_weaknesses
        ]

        print(
            f"{threat.id}: {ids}"
        )

    print(
        "\n========== METADATA =========="
    )

    for key, value in result.metadata.items():
        print(
            f"{key:<35}: {value}"
        )

    # CWE-79 is requested by two Threat objects, but the service
    # cache causes only one repository call for that identifier.
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


def test_cwe_enrichment_preserves_category(
    service: CWEEnrichmentService,
) -> None:
    threat = Threat(
        id="CVE-2021-44228",
        category=ThreatCategory.VULNERABILITY,
        weakness_references=[
            WeaknessReference(
                source="NVD",
                cwe_id="CWE-502",
                resolution_status="resolved",
                resolution_method="explicit_id",
            )
        ],
    )

    result = service.enrich_threat(
        threat
    )

    assert (
        result.threats[0].category
        is ThreatCategory.VULNERABILITY
    )
