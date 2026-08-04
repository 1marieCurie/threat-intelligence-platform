from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from application.services.cwe_lookup_service import (
    CWELookupService,
)
from domain.cwe_weakness import CWEWeakness
from domain.threat import Threat
from domain.weakness_reference import WeaknessReference


@dataclass
class CWEEnrichmentResult:
    """
    Result of an official CWE catalog enrichment operation.

    Threat objects are enriched in place and returned through
    the threats attribute.
    """

    threats: list[Threat]

    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    def enriched_threats(
        self,
    ) -> list[Threat]:
        """
        Return threats containing at least one official CWE entry.
        """
        return [
            threat
            for threat in self.threats
            if threat.official_weaknesses
        ]

    def missing_cwe_ids(
        self,
    ) -> list[str]:
        """
        Return CWE identifiers that were not found locally.
        """
        value = self.metadata.get(
            "missing_cwe_ids",
            [],
        )

        if not isinstance(value, list):
            return []

        return [
            item
            for item in value
            if isinstance(item, str)
        ]


class CWEEnrichmentService:
    """
    Enrich historical Threat objects with locally persisted CWE data.

    The service preserves source-specific WeaknessReference objects
    and adds normalized CWEWeakness objects separately.

    The service no longer accesses a repository directly. All local
    reads are delegated to CWELookupService before Threat mutation.

    This service is transitional. The canonical layer will consume
    CWELookupService directly without depending on Threat.
    """

    CWE_ID_PATTERN = re.compile(
        r"^(?:CWE-)?(\d+)$",
        re.IGNORECASE,
    )

    RESOLVABLE_STATUS = "resolved"

    def __init__(
        self,
        *,
        cwe_lookup: CWELookupService,
    ) -> None:
        if cwe_lookup is None:
            raise ValueError(
                "cwe_lookup must not be None"
            )

        self._cwe_lookup = cwe_lookup

    def enrich_threat(
        self,
        threat: Threat,
    ) -> CWEEnrichmentResult:
        """
        Enrich one Threat object.
        """
        if not isinstance(
            threat,
            Threat,
        ):
            raise TypeError(
                "threat must be a Threat instance."
            )

        return self.enrich_threats(
            [threat]
        )

    def enrich_threats(
        self,
        threats: Iterable[Threat],
    ) -> CWEEnrichmentResult:
        """
        Enrich several Threat objects with official CWE entries.

        All valid CWE identifiers are loaded in one lookup before
        any Threat object is modified.
        """
        normalized_threats = (
            self._validate_threats(
                threats
            )
        )

        requested_cwe_ids: list[str] = []
        requested_cwe_id_set: set[str] = set()

        cwe_ids_by_threat: list[
            list[str]
        ] = []

        total_references = 0
        references_with_cwe_id = 0

        unresolved_references = 0
        placeholder_references = 0
        invalid_references = 0
        skipped_references = 0

        # Première phase :
        # analyser les références sans modifier les Threat.
        for threat in normalized_threats:
            threat_cwe_ids: list[str] = []

            for reference in threat.weakness_references:
                total_references += 1

                if not isinstance(
                    reference,
                    WeaknessReference,
                ):
                    skipped_references += 1
                    continue

                status = self._normalize_status(
                    reference.resolution_status
                )

                if status == "placeholder":
                    placeholder_references += 1
                    skipped_references += 1
                    continue

                if status == "invalid":
                    invalid_references += 1
                    skipped_references += 1
                    continue

                if status == "unresolved":
                    unresolved_references += 1
                    skipped_references += 1
                    continue

                if status != self.RESOLVABLE_STATUS:
                    skipped_references += 1
                    continue

                normalized_cwe_id = (
                    self._normalize_cwe_id(
                        reference.cwe_id
                    )
                )

                if normalized_cwe_id is None:
                    invalid_references += 1
                    skipped_references += 1
                    continue

                references_with_cwe_id += 1

                threat_cwe_ids.append(
                    normalized_cwe_id
                )

                if (
                    normalized_cwe_id
                    not in requested_cwe_id_set
                ):
                    requested_cwe_id_set.add(
                        normalized_cwe_id
                    )

                    requested_cwe_ids.append(
                        normalized_cwe_id
                    )

            cwe_ids_by_threat.append(
                threat_cwe_ids
            )

        # Une seule lecture groupée pour tous les Threat.
        if requested_cwe_ids:
            weaknesses_by_id = (
                self._cwe_lookup
                .find_many_by_cwe_ids(
                    requested_cwe_ids
                )
            )

            repository_queries = 1

        else:
            weaknesses_by_id = {}
            repository_queries = 0

        found_ids: set[str] = set()
        missing_ids: set[str] = set()

        resolved_references = 0
        missing_references = 0

        newly_enriched_threats = 0
        already_enriched_threats = 0
        newly_added_weaknesses = 0
        duplicate_weakness_links = 0

        # Deuxième phase :
        # appliquer les données uniquement après un lookup réussi.
        for threat, threat_cwe_ids in zip(
            normalized_threats,
            cwe_ids_by_threat,
            strict=True,
        ):
            existing_by_id = (
                self._index_existing_weaknesses(
                    threat
                )
            )

            had_official_weaknesses = bool(
                existing_by_id
            )

            added_to_current_threat = 0

            for cwe_id in threat_cwe_ids:
                official_weakness = (
                    weaknesses_by_id.get(
                        cwe_id
                    )
                )

                if official_weakness is None:
                    missing_ids.add(
                        cwe_id
                    )
                    missing_references += 1
                    continue

                found_ids.add(
                    cwe_id
                )
                resolved_references += 1

                if cwe_id in existing_by_id:
                    duplicate_weakness_links += 1
                    continue

                existing_by_id[
                    cwe_id
                ] = official_weakness

                newly_added_weaknesses += 1
                added_to_current_threat += 1

            threat.official_weaknesses = list(
                existing_by_id.values()
            )

            if added_to_current_threat > 0:
                newly_enriched_threats += 1

            elif had_official_weaknesses:
                already_enriched_threats += 1

        metadata: dict[str, Any] = {
            "source": "CWE",
            "status": "SUCCESS",
            "total_threats": len(
                normalized_threats
            ),
            "total_weakness_references": (
                total_references
            ),
            "references_with_cwe_id": (
                references_with_cwe_id
            ),
            "resolved_references": (
                resolved_references
            ),
            "missing_references": (
                missing_references
            ),
            "unresolved_references": (
                unresolved_references
            ),
            "placeholder_references": (
                placeholder_references
            ),
            "invalid_references": (
                invalid_references
            ),
            "skipped_references": (
                skipped_references
            ),
            "requested_unique_cwe_ids": len(
                requested_cwe_ids
            ),
            "found_unique_cwe_ids": len(
                found_ids
            ),
            "missing_unique_cwe_ids": len(
                missing_ids
            ),
            "missing_cwe_ids": sorted(
                missing_ids,
                key=self._cwe_sort_key,
            ),
            "newly_enriched_threats": (
                newly_enriched_threats
            ),
            "already_enriched_threats": (
                already_enriched_threats
            ),
            "newly_added_official_weaknesses": (
                newly_added_weaknesses
            ),
            "duplicate_weakness_links": (
                duplicate_weakness_links
            ),
            "repository_queries": (
                repository_queries
            ),
        }

        return CWEEnrichmentResult(
            threats=normalized_threats,
            metadata=metadata,
        )

    def _index_existing_weaknesses(
        self,
        threat: Threat,
    ) -> dict[str, CWEWeakness]:
        """
        Preserve and deduplicate official weaknesses already stored
        on a Threat.
        """
        result: dict[
            str,
            CWEWeakness,
        ] = {}

        official_weaknesses = getattr(
            threat,
            "official_weaknesses",
            [],
        )

        if not isinstance(
            official_weaknesses,
            list,
        ):
            return result

        for weakness in official_weaknesses:
            if not isinstance(
                weakness,
                CWEWeakness,
            ):
                continue

            normalized_id = (
                self._normalize_cwe_id(
                    weakness.id
                )
            )

            if normalized_id is None:
                continue

            result.setdefault(
                normalized_id,
                weakness,
            )

        return result

    @staticmethod
    def _validate_threats(
        threats: Iterable[Threat],
    ) -> list[Threat]:
        """
        Validate and materialize a Threat iterable.
        """
        if isinstance(
            threats,
            (str, bytes),
        ):
            raise TypeError(
                "threats must be an iterable of Threat objects."
            )

        try:
            normalized_threats = list(
                threats
            )

        except TypeError as error:
            raise TypeError(
                "threats must be an iterable of Threat objects."
            ) from error

        for threat in normalized_threats:
            if not isinstance(
                threat,
                Threat,
            ):
                raise TypeError(
                    "Every threats element must be "
                    "a Threat instance."
                )

        return normalized_threats

    @classmethod
    def _normalize_cwe_id(
        cls,
        value: Any,
    ) -> str | None:
        """
        Normalize a source CWE identifier to CWE-<number>.
        """
        if isinstance(value, bool):
            return None

        if isinstance(value, int):
            if value <= 0:
                return None

            return f"CWE-{value}"

        if not isinstance(value, str):
            return None

        normalized = value.strip()

        if (
            not normalized
            or len(normalized)
            > CWELookupService.MAX_CWE_ID_LENGTH
        ):
            return None

        match = cls.CWE_ID_PATTERN.fullmatch(
            normalized
        )

        if match is None:
            return None

        numeric_id = int(
            match.group(1)
        )

        if numeric_id <= 0:
            return None

        return f"CWE-{numeric_id}"

    @staticmethod
    def _normalize_status(
        value: Any,
    ) -> str:
        """
        Normalize a WeaknessReference resolution status.
        """
        if not isinstance(value, str):
            return ""

        return (
            value
            .replace("\u00a0", " ")
            .strip()
            .lower()
        )

    @staticmethod
    def _cwe_sort_key(
        cwe_id: str,
    ) -> tuple[int, str]:
        """
        Sort canonical CWE identifiers numerically.
        """
        try:
            numeric_part = cwe_id.split(
                "-",
                maxsplit=1,
            )[1]

            return (
                int(numeric_part),
                cwe_id,
            )

        except (
            IndexError,
            ValueError,
        ):
            return (
                10**12,
                cwe_id,
            )