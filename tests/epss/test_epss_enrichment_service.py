from __future__ import annotations

from collections.abc import Iterable
from datetime import date

import pytest

from application.models.epss_snapshot import (
    EPSSSnapshot,
)
from application.services.epss_enrichment_service import (
    EPSSEnrichmentResult,
    EPSSEnrichmentService,
)
from domain.threat import Threat
from domain.threat_category import ThreatCategory


class FakeEPSSLookupService:
    """
    Lookup EPSS déterministe sans accès PostgreSQL.

    Les règles de transaction, de normalisation et de
    validation du repository sont testées séparément
    dans test_epss_lookup_service.py.
    """

    def __init__(
        self,
        *,
        result: dict[
            str,
            EPSSSnapshot,
        ] | None = None,
        error: Exception | None = None,
    ) -> None:
        self.result = (
            {}
            if result is None
            else result
        )

        self.error = error

        self.calls: list[
            list[str | None]
        ] = []

    def find_many_by_cve_ids(
        self,
        cve_ids: Iterable[str | None],
    ) -> dict[str, EPSSSnapshot]:
        provided_cve_ids = list(
            cve_ids
        )

        self.calls.append(
            provided_cve_ids
        )

        if self.error is not None:
            raise self.error

        return dict(
            self.result
        )


def _snapshot(
    *,
    score: float = 0.99999,
    percentile: float = 1.0,
    score_date: date = date(
        2026,
        7,
        30,
    ),
) -> EPSSSnapshot:
    return EPSSSnapshot(
        score=score,
        percentile=percentile,
        score_date=score_date,
    )


def _build_service(
    *,
    lookup_result: dict[
        str,
        EPSSSnapshot,
    ] | None = None,
    lookup_error: Exception | None = None,
) -> tuple[
    EPSSEnrichmentService,
    FakeEPSSLookupService,
]:
    epss_lookup = FakeEPSSLookupService(
        result=lookup_result,
        error=lookup_error,
    )

    service = EPSSEnrichmentService(
        epss_lookup=epss_lookup,  # type: ignore[arg-type]
    )

    return (
        service,
        epss_lookup,
    )


def test_constructor_rejects_missing_lookup(
) -> None:
    with pytest.raises(
        ValueError,
        match="epss_lookup must not be None",
    ):
        EPSSEnrichmentService(
            epss_lookup=None,  # type: ignore[arg-type]
        )


def test_fetch_delegates_to_lookup(
) -> None:
    snapshot = _snapshot()

    service, epss_lookup = _build_service(
        lookup_result={
            "CVE-2021-44228": snapshot,
        },
    )

    result = service.fetch_epss_by_cve_ids(
        [
            " cve-2021-44228 ",
            None,
        ]
    )

    assert result == {
        "CVE-2021-44228": snapshot,
    }

    # La normalisation appartient désormais
    # entièrement à EPSSLookupService.
    assert epss_lookup.calls == [
        [
            " cve-2021-44228 ",
            None,
        ]
    ]


def test_fetch_rejects_historical_date_before_lookup(
) -> None:
    service, epss_lookup = _build_service()

    with pytest.raises(
        ValueError,
        match=(
            "historical EPSS enrichment "
            "is not supported by local storage"
        ),
    ):
        service.fetch_epss_by_cve_ids(
            [
                "CVE-2021-44228",
            ],
            date="2026-07-29",
        )

    assert epss_lookup.calls == []


def test_enriches_single_threat_from_local_snapshot(
) -> None:
    snapshot = _snapshot(
        score=0.99999,
        percentile=0.99998,
        score_date=date(
            2026,
            7,
            30,
        ),
    )

    service, epss_lookup = _build_service(
        lookup_result={
            "CVE-2021-44228": snapshot,
        },
    )

    threat = Threat(
        id="CVE-2021-44228",
        description=(
            "Apache Log4j vulnerability"
        ),
    )

    result = service.enrich_threats(
        [
            threat,
        ]
    )

    assert isinstance(
        result,
        EPSSEnrichmentResult,
    )

    assert result.threats == [
        threat,
    ]

    assert threat.epss_score == 0.99999
    assert threat.epss_percentile == 0.99998
    assert threat.epss_date == "2026-07-30"

    assert result.metadata == {
        "source": "EPSS",
        "storage": "PostgreSQL",
        "requested_cves": 1,
        "epss_records_found": 1,
        "enriched_threats": 1,
        "missing_cves": [],
        "non_cve_threats": 0,
        "date_requested": None,
    }

    assert epss_lookup.calls == [
        [
            "CVE-2021-44228",
        ]
    ]


def test_duplicate_cves_are_loaded_once_and_all_threats_enriched(
) -> None:
    snapshot = _snapshot()

    service, epss_lookup = _build_service(
        lookup_result={
            "CVE-2021-44228": snapshot,
        },
    )

    threats = [
        Threat(
            id="CVE-2021-44228",
            description="NVD record",
        ),
        Threat(
            id="cve-2021-44228",
            description="CISA record",
        ),
        Threat(
            id="GHSA-example",
            external_ids={
                "CVE": [
                    "CVE-2021-44228",
                ],
            },
            description=(
                "GitHub Advisory record"
            ),
        ),
    ]

    result = service.enrich_threats(
        threats
    )

    assert (
        result.metadata[
            "requested_cves"
        ]
        == 1
    )

    assert (
        result.metadata[
            "enriched_threats"
        ]
        == 3
    )

    for threat in threats:
        assert threat.epss_score == 0.99999
        assert threat.epss_percentile == 1.0
        assert threat.epss_date == "2026-07-30"

    assert epss_lookup.calls == [
        [
            "CVE-2021-44228",
        ]
    ]


def test_non_cve_threat_is_preserved_without_enrichment(
) -> None:
    snapshot = _snapshot()

    service, epss_lookup = _build_service(
        lookup_result={
            "CVE-2021-44228": snapshot,
        },
    )

    non_cve_threat = Threat(
        id="GHSA-xxxx-yyyy-zzzz",
    )

    cve_threat = Threat(
        id="CVE-2021-44228",
    )

    result = service.enrich_threats(
        [
            non_cve_threat,
            cve_threat,
        ]
    )

    assert non_cve_threat.epss_score is None

    assert (
        non_cve_threat.epss_percentile
        is None
    )

    assert non_cve_threat.epss_date is None
    assert cve_threat.epss_score == 0.99999

    assert (
        result.metadata[
            "non_cve_threats"
        ]
        == 1
    )

    assert epss_lookup.calls == [
        [
            "CVE-2021-44228",
        ]
    ]


def test_external_cve_identifier_is_supported(
) -> None:
    snapshot = _snapshot(
        score=0.75,
    )

    service, epss_lookup = _build_service(
        lookup_result={
            "CVE-2024-3094": snapshot,
        },
    )

    threat = Threat(
        id="GHSA-example",
        external_ids={
            "CVE": [
                "cve-2024-3094",
            ],
        },
    )

    result = service.enrich_threats(
        [
            threat,
        ]
    )

    assert threat.epss_score == 0.75

    assert (
        result.metadata[
            "requested_cves"
        ]
        == 1
    )

    assert epss_lookup.calls == [
        [
            "CVE-2024-3094",
        ]
    ]


def test_missing_cve_is_reported_in_metadata(
) -> None:
    snapshot = _snapshot()

    service, epss_lookup = _build_service(
        lookup_result={
            "CVE-2021-44228": snapshot,
        },
    )

    known_threat = Threat(
        id="CVE-2021-44228",
    )

    missing_threat = Threat(
        id="CVE-2099-0001",
    )

    result = service.enrich_threats(
        [
            known_threat,
            missing_threat,
        ]
    )

    assert known_threat.epss_score is not None
    assert missing_threat.epss_score is None

    assert (
        result.metadata[
            "epss_records_found"
        ]
        == 1
    )

    assert (
        result.metadata[
            "enriched_threats"
        ]
        == 1
    )

    assert (
        result.metadata[
            "missing_cves"
        ]
        == [
            "CVE-2099-0001",
        ]
    )

    assert epss_lookup.calls == [
        [
            "CVE-2021-44228",
            "CVE-2099-0001",
        ]
    ]


def test_empty_threat_list_skips_lookup(
) -> None:
    service, epss_lookup = _build_service()

    result = service.enrich_threats(
        []
    )

    assert result.threats == []

    assert result.metadata == {
        "source": "EPSS",
        "storage": "PostgreSQL",
        "requested_cves": 0,
        "epss_records_found": 0,
        "enriched_threats": 0,
        "missing_cves": [],
        "non_cve_threats": 0,
        "date_requested": None,
    }

    assert epss_lookup.calls == []


def test_enrich_threats_rejects_non_list(
) -> None:
    service, epss_lookup = _build_service()

    with pytest.raises(
        TypeError,
        match="threats must be a list",
    ):
        service.enrich_threats(
            (  # type: ignore[arg-type]
                Threat(
                    id="CVE-2021-44228",
                ),
            )
        )

    assert epss_lookup.calls == []


def test_enrich_threats_rejects_invalid_element(
) -> None:
    service, epss_lookup = _build_service()

    with pytest.raises(
        TypeError,
        match=(
            "threats must contain only "
            "Threat objects"
        ),
    ):
        service.enrich_threats(
            [
                Threat(
                    id="CVE-2021-44228",
                ),
                "invalid",  # type: ignore[list-item]
            ]
        )

    assert epss_lookup.calls == []


def test_enrichment_preserves_threat_category(
) -> None:
    snapshot = _snapshot()

    service, _ = _build_service(
        lookup_result={
            "CVE-2021-44228": snapshot,
        },
    )

    threat = Threat(
        id="CVE-2021-44228",
        category=(
            ThreatCategory.VULNERABILITY
        ),
    )

    result = service.enrich_threats(
        [
            threat,
        ]
    )

    assert (
        result.threats[0].category
        is ThreatCategory.VULNERABILITY
    )


def test_lookup_failure_preserves_unmodified_threat(
) -> None:
    expected_error = RuntimeError(
        "PostgreSQL read failure"
    )

    service, epss_lookup = _build_service(
        lookup_error=expected_error,
    )

    threat = Threat(
        id="CVE-2021-44228",
    )

    with pytest.raises(
        RuntimeError,
        match="PostgreSQL read failure",
    ) as raised_error:
        service.enrich_threats(
            [
                threat,
            ]
        )

    assert raised_error.value is expected_error

    assert threat.epss_score is None
    assert threat.epss_percentile is None
    assert threat.epss_date is None

    assert epss_lookup.calls == [
        [
            "CVE-2021-44228",
        ]
    ]


def test_enrich_threats_rejects_historical_date(
) -> None:
    service, epss_lookup = _build_service()

    with pytest.raises(
        ValueError,
        match=(
            "historical EPSS enrichment "
            "is not supported by local storage"
        ),
    ):
        service.enrich_threats(
            [
                Threat(
                    id="CVE-2021-44228",
                ),
            ],
            date="2026-07-29",
        )

    assert epss_lookup.calls == []