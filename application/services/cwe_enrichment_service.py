from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from application.ports.outbound.cwe_repository import (
    CWERepository,
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
        Return CWE identifiers that were not found in the catalog.
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
    Enrich Threat objects using the official MITRE CWE catalog.

    The service preserves source-specific WeaknessReference objects
    and adds normalized CWEWeakness objects separately.

    Important behavior:
    - only resolved references with a valid CWE ID are searched;
    - placeholder, invalid and unresolved references are skipped;
    - several source references to the same CWE produce only one
      official CWEWeakness per Threat;
    - repository lookups are cached during one enrichment run;
    - missing CWE IDs do not stop the enrichment process.
    """

    CWE_ID_PATTERN = re.compile(
        r"^(?:CWE-)?(\d+)$",
        re.IGNORECASE,
    )

    RESOLVABLE_STATUS = "resolved"

    NON_RESOLVABLE_STATUSES = {
        "unresolved",
        "placeholder",
        "invalid",
    }

    def __init__(
        self,
        repository: CWERepository,
    ) -> None:
        if repository is None:
            raise ValueError(
                "repository is required."
            )

        self.repository = repository

    # ============================================================
    # Public operations
    # ============================================================

    def enrich_threat(
        self,
        threat: Threat,
    ) -> CWEEnrichmentResult:
        """
        Enrich one Threat object.
        """

        if not isinstance(threat, Threat):
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

        Threat objects are modified in place.
        """

        normalized_threats = (
            self._validate_threats(
                threats
            )
        )

        cache: dict[
            str,
            CWEWeakness | None,
        ] = {}

        requested_ids: set[str] = set()
        found_ids: set[str] = set()
        missing_ids: set[str] = set()

        total_references = 0
        references_with_cwe_id = 0
        resolved_references = 0
        missing_references = 0

        unresolved_references = 0
        placeholder_references = 0
        invalid_references = 0
        skipped_references = 0

        newly_enriched_threats = 0
        already_enriched_threats = 0
        newly_added_weaknesses = 0
        duplicate_weakness_links = 0

        for threat in normalized_threats:
            existing_by_id = (
                self._index_existing_weaknesses(
                    threat
                )
            )

            had_official_weaknesses = bool(
                existing_by_id
            )

            added_to_current_threat = 0

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
                requested_ids.add(
                    normalized_cwe_id
                )

                official_weakness = (
                    self._find_with_cache(
                        cwe_id=normalized_cwe_id,
                        cache=cache,
                    )
                )

                if official_weakness is None:
                    missing_ids.add(
                        normalized_cwe_id
                    )
                    missing_references += 1
                    continue

                found_ids.add(
                    normalized_cwe_id
                )
                resolved_references += 1

                official_id = (
                    self._normalize_cwe_id(
                        official_weakness.id
                    )
                )

                if official_id is None:
                    official_id = normalized_cwe_id

                if official_id in existing_by_id:
                    duplicate_weakness_links += 1
                    continue

                existing_by_id[
                    official_id
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
                requested_ids
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
            "repository_queries": len(
                cache
            ),
        }

        return CWEEnrichmentResult(
            threats=normalized_threats,
            metadata=metadata,
        )

    # ============================================================
    # Repository access
    # ============================================================

    def _find_with_cache(
        self,
        *,
        cwe_id: str,
        cache: dict[
            str,
            CWEWeakness | None,
        ],
    ) -> CWEWeakness | None:
        """
        Retrieve one official CWE and cache the result.

        Missing values are cached as None to avoid repeated queries.
        """

        if cwe_id not in cache:
            weakness = self.repository.find_by_id(
                cwe_id
            )

            if (
                weakness is not None
                and not isinstance(
                    weakness,
                    CWEWeakness,
                )
            ):
                raise TypeError(
                    "CWERepository.find_by_id() must return "
                    "CWEWeakness or None."
                )

            cache[cwe_id] = weakness

        return cache[cwe_id]

    # ============================================================
    # Existing enrichment
    # ============================================================

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

    # ============================================================
    # Input validation
    # ============================================================

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

    # ============================================================
    # Normalization helpers
    # ============================================================

    @classmethod
    def _normalize_cwe_id(
        cls,
        value: Any,
    ) -> str | None:
        """
        Normalize a CWE identifier to CWE-<number>.

        Accepted values:
            CWE-79
            cwe-79
            79
            "79"
            CWE-00079
            "00079"
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

        if not normalized:
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