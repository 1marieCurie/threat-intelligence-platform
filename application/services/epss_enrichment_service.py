from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from application.models.epss_snapshot import (
    EPSSSnapshot,
)
from application.services.epss_lookup_service import (
    EPSSLookupService,
)
from domain.threat import Threat


_CVE_PATTERN = re.compile(
    r"^CVE-\d{4}-\d{4,}$"
)


@dataclass(slots=True)
class EPSSEnrichmentResult:
    """
    Résultat de l'enrichissement local
    d'une liste de menaces avec EPSS.
    """

    threats: list[Threat] = field(
        default_factory=list
    )

    metadata: dict[str, object] = field(
        default_factory=dict
    )


class EPSSEnrichmentService:
    """
    Enrichit les objets Threat historiques avec
    les snapshots EPSS persistés localement.

    Ce service ne contacte jamais directement FIRST
    et ne connaît plus l'Unit of Work.

    Flux transitoire :

    Threat
        -> extraction des identifiants CVE
        -> EPSSLookupService
        -> application des snapshots aux objets Threat

    La future couche canonique utilisera directement
    EPSSLookupService sans passer par ce service.
    """

    def __init__(
        self,
        *,
        epss_lookup: EPSSLookupService,
    ) -> None:
        if epss_lookup is None:
            raise ValueError(
                "epss_lookup must not be None"
            )

        self._epss_lookup = epss_lookup

    def fetch_epss_by_cve_ids(
        self,
        cve_ids: Iterable[str | None],
        date: str | None = None,
    ) -> dict[str, EPSSSnapshot]:
        """
        Façade transitoire conservée pour compatibilité.

        La lecture, la normalisation et les contrôles
        sont entièrement délégués à EPSSLookupService.
        """
        self._reject_historical_date(
            date
        )

        return (
            self._epss_lookup
            .find_many_by_cve_ids(
                cve_ids
            )
        )

    def enrich_threats(
        self,
        threats: list[Threat],
        date: str | None = None,
    ) -> EPSSEnrichmentResult:
        """
        Enrichit localement une liste de menaces.

        Les menaces sans identifiant CVE sont
        conservées sans modification.
        """
        if not isinstance(
            threats,
            list,
        ):
            raise TypeError(
                "threats must be a list"
            )

        if any(
            not isinstance(
                threat,
                Threat,
            )
            for threat in threats
        ):
            raise TypeError(
                "threats must contain only "
                "Threat objects"
            )

        self._reject_historical_date(
            date
        )

        cve_ids = (
            self
            ._extract_unique_cve_ids_from_threats(
                threats
            )
        )

        non_cve_threats = (
            self._count_non_cve_threats(
                threats
            )
        )

        if not cve_ids:
            return EPSSEnrichmentResult(
                threats=threats,
                metadata=self._build_metadata(
                    requested_cves=0,
                    epss_records_found=0,
                    enriched_threats=0,
                    missing_cves=[],
                    non_cve_threats=(
                        non_cve_threats
                    ),
                ),
            )

        epss_lookup = (
            self.fetch_epss_by_cve_ids(
                cve_ids
            )
        )

        enriched_count = (
            self._apply_epss_to_threats(
                threats=threats,
                epss_lookup=epss_lookup,
            )
        )

        missing_cves = [
            cve_id
            for cve_id in cve_ids
            if cve_id not in epss_lookup
        ]

        return EPSSEnrichmentResult(
            threats=threats,
            metadata=self._build_metadata(
                requested_cves=len(
                    cve_ids
                ),
                epss_records_found=len(
                    epss_lookup
                ),
                enriched_threats=(
                    enriched_count
                ),
                missing_cves=missing_cves,
                non_cve_threats=(
                    non_cve_threats
                ),
            ),
        )

    @staticmethod
    def _build_metadata(
        *,
        requested_cves: int,
        epss_records_found: int,
        enriched_threats: int,
        missing_cves: list[str],
        non_cve_threats: int,
    ) -> dict[str, object]:
        return {
            "source": "EPSS",
            "storage": "PostgreSQL",
            "requested_cves": requested_cves,
            "epss_records_found": (
                epss_records_found
            ),
            "enriched_threats": (
                enriched_threats
            ),
            "missing_cves": missing_cves,
            "non_cve_threats": (
                non_cve_threats
            ),
            "date_requested": None,
        }

    def _extract_unique_cve_ids_from_threats(
        self,
        threats: list[Threat],
    ) -> list[str]:
        candidates: list[str | None] = []

        for threat in threats:
            candidates.append(
                threat.id
            )

            external_cve_ids = (
                threat.external_ids.get(
                    "CVE",
                    [],
                )
            )

            if isinstance(
                external_cve_ids,
                list,
            ):
                candidates.extend(
                    external_cve_ids
                )

        return self._normalize_cve_ids(
            candidates
        )

    def _get_candidate_cve_ids(
        self,
        threat: Threat,
    ) -> list[str]:
        candidates: list[str | None] = [
            threat.id
        ]

        external_cve_ids = (
            threat.external_ids.get(
                "CVE",
                [],
            )
        )

        if isinstance(
            external_cve_ids,
            list,
        ):
            candidates.extend(
                external_cve_ids
            )

        return self._normalize_cve_ids(
            candidates
        )

    def _apply_epss_to_threats(
        self,
        *,
        threats: list[Threat],
        epss_lookup: Mapping[
            str,
            EPSSSnapshot,
        ],
    ) -> int:
        enriched_count = 0

        for threat in threats:
            snapshot: EPSSSnapshot | None = None

            for cve_id in (
                self._get_candidate_cve_ids(
                    threat
                )
            ):
                snapshot = epss_lookup.get(
                    cve_id
                )

                if snapshot is not None:
                    break

            if snapshot is None:
                continue

            threat.epss_score = (
                snapshot.score
            )

            threat.epss_percentile = (
                snapshot.percentile
            )

            threat.epss_date = (
                snapshot.score_date.isoformat()
            )

            enriched_count += 1

        return enriched_count

    def _count_non_cve_threats(
        self,
        threats: list[Threat],
    ) -> int:
        return sum(
            1
            for threat in threats
            if not self._get_candidate_cve_ids(
                threat
            )
        )

    @staticmethod
    def _normalize_cve_ids(
        cve_ids: Iterable[str | None],
    ) -> list[str]:
        normalized_cve_ids: list[str] = []
        seen: set[str] = set()

        for cve_id in cve_ids:
            if cve_id is None:
                continue

            if not isinstance(
                cve_id,
                str,
            ):
                continue

            normalized_cve_id = (
                cve_id
                .strip()
                .upper()
            )

            if not _CVE_PATTERN.fullmatch(
                normalized_cve_id
            ):
                continue

            if normalized_cve_id in seen:
                continue

            seen.add(
                normalized_cve_id
            )

            normalized_cve_ids.append(
                normalized_cve_id
            )

        return normalized_cve_ids

    @staticmethod
    def _reject_historical_date(
        requested_date: str | None,
    ) -> None:
        if requested_date is not None:
            raise ValueError(
                "historical EPSS enrichment "
                "is not supported by local storage"
            )