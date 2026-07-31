from __future__ import annotations

from datetime import date
from pathlib import Path
from unittest.mock import patch

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = PROJECT_ROOT / ".env"

load_dotenv(
    dotenv_path=ENV_FILE,
    override=False,
)


import pytest

from domain.threat import Threat
from infrastructure.bootstrap.epss_enrichment import (
    build_epss_enrichment_service,
)


TARGET_CVE_IDS = [
    "CVE-2021-44228",
    "CVE-2024-3094",
]


@pytest.mark.integration
def test_enriches_threats_from_postgresql_without_first_call(
) -> None:
    """
    Vérifie le parcours réel d'enrichissement local.

    Précondition :
        Les deux CVE ont déjà été synchronisés dans
        normalized.epss_score.

    Le test interdit tout appel HTTP afin de garantir que
    l'enrichissement dépend uniquement de PostgreSQL.
    """
    service = build_epss_enrichment_service()

    threats = [
        Threat(
            id=cve_id,
        )
        for cve_id in TARGET_CVE_IDS
    ]

    with patch(
        "requests.sessions.Session.request",
        side_effect=AssertionError(
            "EPSS enrichment must not call FIRST"
        ),
    ):
        result = service.enrich_threats(
            threats
        )

    assert result.threats == threats

    assert result.metadata == {
        "source": "EPSS",
        "storage": "PostgreSQL",
        "requested_cves": 2,
        "epss_records_found": 2,
        "enriched_threats": 2,
        "missing_cves": [],
        "non_cve_threats": 0,
        "date_requested": None,
    }

    for threat in threats:
        assert threat.epss_score is not None
        assert threat.epss_percentile is not None
        assert threat.epss_date is not None

        assert isinstance(
            threat.epss_score,
            float,
        )

        assert isinstance(
            threat.epss_percentile,
            float,
        )

        assert (
            0.0
            <= threat.epss_score
            <= 1.0
        )

        assert (
            0.0
            <= threat.epss_percentile
            <= 1.0
        )

        parsed_score_date = (
            date.fromisoformat(
                threat.epss_date
            )
        )

        assert isinstance(
            parsed_score_date,
            date,
        )


@pytest.mark.integration
def test_local_enrichment_reports_missing_cve(
) -> None:
    """
    Vérifie qu'une CVE absente de PostgreSQL est signalée
    sans déclencher d'appel FIRST.
    """
    service = build_epss_enrichment_service()

    known_threat = Threat(
        id="CVE-2021-44228",
    )

    missing_threat = Threat(
        id="CVE-2099-999999",
    )

    with patch(
        "requests.sessions.Session.request",
        side_effect=AssertionError(
            "EPSS enrichment must not call FIRST"
        ),
    ):
        result = service.enrich_threats(
            [
                known_threat,
                missing_threat,
            ]
        )

    assert known_threat.epss_score is not None

    assert missing_threat.epss_score is None
    assert missing_threat.epss_percentile is None
    assert missing_threat.epss_date is None

    assert (
        result.metadata[
            "requested_cves"
        ]
        == 2
    )

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
            "CVE-2099-999999",
        ]
    )