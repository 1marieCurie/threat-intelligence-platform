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
from domain.threat_category import ThreatCategory
from domain.weakness_reference import WeaknessReference


class FakeCWELookupService:
    """
    Deterministic CWE lookup without PostgreSQL access.
    """

    def __init__(
        self,
        *,
        result: dict[
            str,
            CWEWeakness,
        ] | None = None,
        error: Exception | None = None,
    ) -> None:
        self.result = dict(
            result or {}
        )
        self.error = error

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

        if self.error is not None:
            raise self.error

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
def cwe_502() -> CWEWeakness:
    return CWEWeakness(
        id="CWE-502",
        name="Deserialization of Untrusted Data",
        description="Official CWE-502 description.",
    )


def _build_service(
    *,
    lookup_result: dict[
        str,
        CWEWeakness,
    ] | None = None,
    lookup_error: Exception | None = None,
) -> tuple[
    CWEEnrichmentService,
    FakeCWELookupService,
]:
    lookup = FakeCWELookupService(
        result=lookup_result,
        error=lookup_error,
    )

    service = CWEEnrichmentService(
        cwe_lookup=lookup,  # type: ignore[arg-type]
    )

    return (
        service,
        lookup,
    )


def test_constructor_rejects_missing_lookup(
) -> None:
    with pytest.raises(
        ValueError,
        match="cwe_lookup must not be None",
    ):
        CWEEnrichmentService(
            cwe_lookup=None,  # type: ignore[arg-type]
        )


def test_enrich_single_threat(
    cwe_79: CWEWeakness,
) -> None:
    service, lookup = _build_service(
        lookup_result={
            "CWE-79": cwe_79,
        },
    )

    threat = Threat(
        id="CVE-2026-0001",
        weakness_references=[
            WeaknessReference(
                source="NVD",
                cwe_id="CWE-79",
                resolution_status="resolved",
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
    ] == 1


def test_enrichment_preserves_source_reference(
    cwe_79: CWEWeakness,
) -> None:
    service, _ = _build_service(
        lookup_result={
            "CWE-79": cwe_79,
        },
    )

    reference = WeaknessReference(
        source="GITHUB_ADVISORY",
        cwe_id="CWE-79",
        source_description="XSS",
        origin="github_advisory",
        resolution_status="resolved",
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


def test_enrichment_normalizes_reference_identifiers(
    cwe_79: CWEWeakness,
) -> None:
    service, lookup = _build_service(
        lookup_result={
            "CWE-79": cwe_79,
        },
    )

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

    assert lookup.calls == [
        [
            "CWE-79",
        ]
    ]

    assert threat.official_weaknesses == [
        cwe_79,
    ]


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
def test_non_resolvable_reference_is_skipped(
    status: str,
    metadata_key: str,
) -> None:
    service, lookup = _build_service()

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

    assert lookup.calls == []
    assert threat.official_weaknesses == []

    assert result.metadata[
        metadata_key
    ] == 1

    assert result.metadata[
        "skipped_references"
    ] == 1


def test_resolved_reference_without_id_is_invalid(
) -> None:
    service, lookup = _build_service()

    threat = Threat(
        id="CVE-2026-0004",
        weakness_references=[
            WeaknessReference(
                source="MITRE",
                cwe_id=None,
                resolution_status="resolved",
            )
        ],
    )

    result = service.enrich_threat(
        threat
    )

    assert lookup.calls == []

    assert result.metadata[
        "invalid_references"
    ] == 1

    assert result.metadata[
        "skipped_references"
    ] == 1


def test_unknown_resolution_status_is_skipped(
) -> None:
    service, lookup = _build_service()

    threat = Threat(
        id="CVE-2026-0005",
        weakness_references=[
            WeaknessReference(
                source="NVD",
                cwe_id="CWE-79",
                resolution_status="unknown",
            )
        ],
    )

    result = service.enrich_threat(
        threat
    )

    assert lookup.calls == []

    assert result.metadata[
        "skipped_references"
    ] == 1


def test_duplicate_references_create_one_official_link(
    cwe_502: CWEWeakness,
) -> None:
    service, lookup = _build_service(
        lookup_result={
            "CWE-502": cwe_502,
        },
    )

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

    assert threat.official_weaknesses == [
        cwe_502,
    ]

    assert lookup.calls == [
        [
            "CWE-502",
        ]
    ]

    assert result.metadata[
        "resolved_references"
    ] == 3

    assert result.metadata[
        "duplicate_weakness_links"
    ] == 2


def test_lookup_is_shared_across_threats(
    cwe_79: CWEWeakness,
) -> None:
    service, lookup = _build_service(
        lookup_result={
            "CWE-79": cwe_79,
        },
    )

    threats = [
        Threat(
            id="CVE-2026-1001",
            weakness_references=[
                WeaknessReference(
                    source="NVD",
                    cwe_id="CWE-79",
                    resolution_status="resolved",
                )
            ],
        ),
        Threat(
            id="CVE-2026-1002",
            weakness_references=[
                WeaknessReference(
                    source="MITRE",
                    cwe_id="CWE-79",
                    resolution_status="resolved",
                )
            ],
        ),
    ]

    result = service.enrich_threats(
        threats
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


def test_multiple_unique_ids_use_one_lookup(
    cwe_79: CWEWeakness,
    cwe_89: CWEWeakness,
) -> None:
    service, lookup = _build_service(
        lookup_result={
            "CWE-79": cwe_79,
            "CWE-89": cwe_89,
        },
    )

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

    assert lookup.calls == [
        [
            "CWE-79",
            "CWE-89",
        ]
    ]

    assert threat.official_weaknesses == [
        cwe_79,
        cwe_89,
    ]

    assert result.metadata[
        "repository_queries"
    ] == 1

    assert result.metadata[
        "requested_unique_cwe_ids"
    ] == 2


def test_existing_official_weakness_is_preserved(
    cwe_79: CWEWeakness,
) -> None:
    service, _ = _build_service(
        lookup_result={
            "CWE-79": cwe_79,
        },
    )

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

    assert result.metadata[
        "duplicate_weakness_links"
    ] == 1

    assert result.metadata[
        "already_enriched_threats"
    ] == 1


def test_existing_official_weaknesses_are_deduplicated(
    cwe_79: CWEWeakness,
) -> None:
    service, lookup = _build_service()

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

    assert lookup.calls == []

    assert threat.official_weaknesses == [
        cwe_79,
    ]


def test_missing_cwe_does_not_stop_enrichment(
    cwe_79: CWEWeakness,
) -> None:
    service, lookup = _build_service(
        lookup_result={
            "CWE-79": cwe_79,
        },
    )

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

    assert lookup.calls == [
        [
            "CWE-999999",
            "CWE-79",
        ]
    ]

    assert threat.official_weaknesses == [
        cwe_79,
    ]

    assert result.metadata[
        "missing_references"
    ] == 1

    assert result.missing_cwe_ids() == [
        "CWE-999999",
    ]


def test_missing_cwe_is_counted_per_reference(
) -> None:
    service, lookup = _build_service()

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

    assert lookup.calls == [
        [
            "CWE-999999",
        ]
    ]

    assert result.metadata[
        "missing_references"
    ] == 2

    assert result.metadata[
        "missing_unique_cwe_ids"
    ] == 1


def test_empty_collection_skips_lookup(
) -> None:
    service, lookup = _build_service()

    result = service.enrich_threats(
        []
    )

    assert result.threats == []
    assert lookup.calls == []

    assert result.metadata[
        "total_threats"
    ] == 0

    assert result.metadata[
        "repository_queries"
    ] == 0


def test_result_helpers(
    cwe_79: CWEWeakness,
) -> None:
    service, _ = _build_service(
        lookup_result={
            "CWE-79": cwe_79,
        },
    )

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

    plain = Threat(
        id="CVE-2026-4002",
    )

    result = service.enrich_threats(
        [
            enriched,
            plain,
        ]
    )

    assert result.enriched_threats() == [
        enriched,
    ]

    assert result.missing_cwe_ids() == []


@pytest.mark.parametrize(
    "invalid_threat",
    [
        None,
        "CVE-2026-0001",
        {},
        123,
    ],
)
def test_enrich_threat_rejects_invalid_type(
    invalid_threat: Any,
) -> None:
    service, lookup = _build_service()

    with pytest.raises(
        TypeError,
        match="threat must be a Threat instance",
    ):
        service.enrich_threat(
            invalid_threat
        )

    assert lookup.calls == []


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
def test_enrich_threats_rejects_invalid_collection(
    invalid_collection: Any,
) -> None:
    service, lookup = _build_service()

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

    assert lookup.calls == []


def test_enrich_threats_rejects_invalid_element(
) -> None:
    service, lookup = _build_service()

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

    assert lookup.calls == []


@pytest.mark.parametrize(
    (
        "raw_value",
        "expected",
    ),
    [
        ("CWE-79", "CWE-79"),
        ("cwe-79", "CWE-79"),
        ("79", "CWE-79"),
        (79, "CWE-79"),
        ("00079", "CWE-79"),
        ("CWE-00079", "CWE-79"),
        (" CWE-502 ", "CWE-502"),
    ],
)
def test_normalize_cwe_id(
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
        "CWE-" + ("9" * 40),
    ],
)
def test_normalize_cwe_id_rejects_invalid_value(
    invalid_value: Any,
) -> None:
    assert (
        CWEEnrichmentService._normalize_cwe_id(
            invalid_value
        )
        is None
    )


def test_enrichment_preserves_category(
    cwe_79: CWEWeakness,
) -> None:
    service, _ = _build_service(
        lookup_result={
            "CWE-79": cwe_79,
        },
    )

    threat = Threat(
        id="CVE-2026-6001",
        category=ThreatCategory.VULNERABILITY,
        weakness_references=[
            WeaknessReference(
                source="NVD",
                cwe_id="CWE-79",
                resolution_status="resolved",
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


def test_lookup_failure_preserves_all_threats(
    cwe_79: CWEWeakness,
) -> None:
    expected_error = RuntimeError(
        "PostgreSQL read failure"
    )

    service, lookup = _build_service(
        lookup_error=expected_error,
    )

    first = Threat(
        id="CVE-2026-7001",
        weakness_references=[
            WeaknessReference(
                source="NVD",
                cwe_id="CWE-79",
                resolution_status="resolved",
            )
        ],
    )

    second = Threat(
        id="CVE-2026-7002",
        official_weaknesses=[
            cwe_79,
            cwe_79,
        ],
        weakness_references=[
            WeaknessReference(
                source="MITRE",
                cwe_id="CWE-89",
                resolution_status="resolved",
            )
        ],
    )

    with pytest.raises(
        RuntimeError,
        match="PostgreSQL read failure",
    ) as raised_error:
        service.enrich_threats(
            [
                first,
                second,
            ]
        )

    assert raised_error.value is expected_error

    assert lookup.calls == [
        [
            "CWE-79",
            "CWE-89",
        ]
    ]

    assert first.official_weaknesses == []

    # Aucune mutation avant la réussite du lookup.
    assert second.official_weaknesses == [
        cwe_79,
        cwe_79,
    ]