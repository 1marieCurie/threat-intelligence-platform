from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from application.models.epss_snapshot import (
    EPSSSnapshot,
)
from application.ports.outbound.unit_of_work import (
    UnitOfWork,
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
    Enrichit des objets Threat avec les scores
    EPSS persistés localement.

    Ce service ne contacte jamais directement FIRST.

    Flux actuel :

    Threat
        -> extraction des identifiants CVE
        -> lecture groupée depuis PostgreSQL
        -> fermeture de la transaction
        -> application des scores aux objets Threat

    Ce service est transitoire : la future couche
    canonique devra consommer directement le lookup
    EPSS sans dépendre du modèle historique Threat.
    """

    DEFAULT_MAX_CVE_IDS = 50_000

    def __init__(
        self,
        *,
        unit_of_work: UnitOfWork,
        max_cve_ids: int = DEFAULT_MAX_CVE_IDS,
    ) -> None:
        if unit_of_work is None:
            raise ValueError(
                "unit_of_work must not be None"
            )

        self._validate_positive_integer(
            value=max_cve_ids,
            field_name="max_cve_ids",
        )

        self._unit_of_work = unit_of_work
        self._max_cve_ids = max_cve_ids

    def fetch_epss_by_cve_ids(
        self,
        cve_ids: Iterable[str | None],
        date: str | None = None,
    ) -> dict[str, EPSSSnapshot]:
        """
        Relit les derniers scores EPSS persistés
        pour une collection d'identifiants CVE.

        Une seule lecture groupée est effectuée.

        La table normalized.epss_score conserve
        actuellement uniquement le dernier snapshot
        connu par CVE. Une date historique ne peut
        donc pas être honorée localement.
        """

        self._reject_historical_date(
            date
        )

        normalized_cve_ids = (
            self._normalize_cve_ids(
                cve_ids
            )
        )

        if not normalized_cve_ids:
            return {}

        if (
            len(normalized_cve_ids)
            > self._max_cve_ids
        ):
            raise ValueError(
                "cve_ids exceeds the configured "
                f"limit of {self._max_cve_ids}"
            )

        # La transaction reste limitée à la lecture SQL.
        # Toute mutation métier est réalisée après
        # la fermeture de la session.
        with self._unit_of_work as unit_of_work:
            snapshots = (
                unit_of_work.epss_scores
                .find_many_by_cve_ids(
                    normalized_cve_ids
                )
            )

        return self._validate_and_order_snapshots(
            requested_cve_ids=(
                normalized_cve_ids
            ),
            snapshots=snapshots,
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

    def _normalize_cve_ids(
        self,
        cve_ids: Iterable[str | None],
    ) -> list[str]:
        if isinstance(
            cve_ids,
            (str, bytes),
        ):
            raise TypeError(
                "cve_ids must be an iterable "
                "of identifiers"
            )

        try:
            iterator = iter(
                cve_ids
            )

        except TypeError as error:
            raise TypeError(
                "cve_ids must be iterable"
            ) from error

        normalized_cve_ids: list[str] = []
        seen: set[str] = set()

        for cve_id in iterator:
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
    def _validate_and_order_snapshots(
        *,
        requested_cve_ids: list[str],
        snapshots: Mapping[
            str,
            EPSSSnapshot,
        ],
    ) -> dict[str, EPSSSnapshot]:
        if not isinstance(
            snapshots,
            Mapping,
        ):
            raise TypeError(
                "epss repository result "
                "must be a mapping"
            )

        unexpected_cve_ids = (
            set(snapshots)
            - set(requested_cve_ids)
        )

        if unexpected_cve_ids:
            raise RuntimeError(
                "epss repository returned "
                "unexpected CVE identifiers"
            )

        ordered_snapshots: dict[
            str,
            EPSSSnapshot,
        ] = {}

        for cve_id in requested_cve_ids:
            snapshot = snapshots.get(
                cve_id
            )

            if snapshot is None:
                continue

            if not isinstance(
                snapshot,
                EPSSSnapshot,
            ):
                raise TypeError(
                    "epss repository values must "
                    "be EPSSSnapshot instances"
                )

            ordered_snapshots[
                cve_id
            ] = snapshot

        return ordered_snapshots

    @staticmethod
    def _reject_historical_date(
        requested_date: str | None,
    ) -> None:
        if requested_date is not None:
            raise ValueError(
                "historical EPSS enrichment "
                "is not supported by local storage"
            )

    @staticmethod
    def _validate_positive_integer(
        *,
        value: int,
        field_name: str,
    ) -> None:
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
        ):
            raise TypeError(
                f"{field_name} must be an integer"
            )

        if value < 1:
            raise ValueError(
                f"{field_name} must be "
                "greater than zero"
            )