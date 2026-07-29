from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

from domain.cwe_weakness import CWEWeakness


class CWEWeaknessMapper:
    """
    Map MITRE CWE API payloads to CWEWeakness domain objects.

    The mapper:
    - validates required identity fields;
    - safely copies structured collections;
    - normalizes CWE and CAPEC identifiers;
    - prevents unbounded external collections;
    - does not retain the complete external payload in memory.
    """

    CWE_ID_PATTERN = re.compile(
        r"^(?:CWE-)?0*([1-9][0-9]*)$",
        re.IGNORECASE,
    )

    CAPEC_ID_PATTERN = re.compile(
        r"^(?:CAPEC-)?0*([1-9][0-9]*)$",
        re.IGNORECASE,
    )

    MAX_COLLECTION_ITEMS = 2_000
    MAX_TEXT_LENGTH = 500_000

    @classmethod
    def map_payload(
        cls,
        payload: Mapping[str, Any],
        *,
        catalog_version: str | None = None,
        catalog_date: str | None = None,
    ) -> list[CWEWeakness]:
        """
        Map a MITRE response containing a Weaknesses collection.
        """

        if not isinstance(
            payload,
            Mapping,
        ):
            raise TypeError(
                "payload must be a mapping"
            )

        raw_weaknesses = payload.get(
            "Weaknesses"
        )

        if not isinstance(
            raw_weaknesses,
            list,
        ):
            raise ValueError(
                "payload must contain a Weaknesses list"
            )

        cls._validate_collection_size(
            raw_weaknesses,
            field_name="Weaknesses",
        )

        weaknesses_by_id: dict[
            str,
            CWEWeakness,
        ] = {}

        for raw_weakness in raw_weaknesses:
            if not isinstance(
                raw_weakness,
                Mapping,
            ):
                raise ValueError(
                    "Every Weaknesses element "
                    "must be a mapping"
                )

            weakness = cls.map_weakness(
                raw_weakness,
                catalog_version=catalog_version,
                catalog_date=catalog_date,
            )

            existing = weaknesses_by_id.get(
                weakness.id
            )

            if (
                existing is not None
                and existing != weakness
            ):
                raise ValueError(
                    "Conflicting duplicate CWE "
                    f"entry: {weakness.id}"
                )

            weaknesses_by_id.setdefault(
                weakness.id,
                weakness,
            )

        return list(
            weaknesses_by_id.values()
        )

    @classmethod
    def map_weakness(
        cls,
        raw: Mapping[str, Any],
        *,
        catalog_version: str | None = None,
        catalog_date: str | None = None,
    ) -> CWEWeakness:
        """
        Map one MITRE weakness object.
        """

        if not isinstance(
            raw,
            Mapping,
        ):
            raise TypeError(
                "raw weakness must be a mapping"
            )

        cwe_id = cls._normalize_cwe_id(
            raw.get("ID")
        )

        name = cls._required_text(
            raw.get("Name"),
            field_name="Name",
        )

        description = cls._required_text(
            raw.get("Description"),
            field_name="Description",
        )

        mapping_notes = raw.get(
            "MappingNotes"
        )

        mapping_usage: str | None = None
        mapping_rationale: str | None = None

        if mapping_notes is not None:
            if not isinstance(
                mapping_notes,
                Mapping,
            ):
                raise ValueError(
                    "MappingNotes must be a mapping"
                )

            mapping_usage = cls._optional_text(
                mapping_notes.get("Usage"),
                field_name="MappingNotes.Usage",
            )

            mapping_rationale = (
                cls._optional_text(
                    mapping_notes.get(
                        "Rationale"
                    ),
                    field_name=(
                        "MappingNotes.Rationale"
                    ),
                )
            )

        return CWEWeakness(
            id=cwe_id,
            name=name,
            description=description,
            abstraction=cls._optional_text(
                raw.get("Abstraction"),
                field_name="Abstraction",
            ),
            structure=cls._optional_text(
                raw.get("Structure"),
                field_name="Structure",
            ),
            status=cls._optional_text(
                raw.get("Status"),
                field_name="Status",
            ),
            extended_description=(
                cls._optional_text(
                    raw.get(
                        "ExtendedDescription"
                    ),
                    field_name=(
                        "ExtendedDescription"
                    ),
                )
            ),
            likelihood_of_exploit=(
                cls._optional_text(
                    raw.get(
                        "LikelihoodOfExploit"
                    ),
                    field_name=(
                        "LikelihoodOfExploit"
                    ),
                )
            ),
            mapping_usage=mapping_usage,
            mapping_rationale=(
                mapping_rationale
            ),
            relationships=(
                cls._mapping_collection(
                    raw.get(
                        "RelatedWeaknesses"
                    ),
                    field_name=(
                        "RelatedWeaknesses"
                    ),
                )
            ),
            consequences=(
                cls._mapping_collection(
                    raw.get(
                        "CommonConsequences"
                    ),
                    field_name=(
                        "CommonConsequences"
                    ),
                )
            ),
            mitigations=(
                cls._mapping_collection(
                    raw.get(
                        "PotentialMitigations"
                    ),
                    field_name=(
                        "PotentialMitigations"
                    ),
                )
            ),
            detection_methods=(
                cls._mapping_collection(
                    raw.get(
                        "DetectionMethods"
                    ),
                    field_name=(
                        "DetectionMethods"
                    ),
                )
            ),
            applicable_platforms=(
                cls._map_platforms(
                    raw.get(
                        "ApplicablePlatforms"
                    )
                )
            ),
            modes_of_introduction=(
                cls._mapping_collection(
                    raw.get(
                        "ModesOfIntroduction"
                    ),
                    field_name=(
                        "ModesOfIntroduction"
                    ),
                )
            ),
            alternate_terms=(
                cls._map_alternate_terms(
                    raw.get(
                        "AlternateTerms"
                    )
                )
            ),
            related_capec_ids=(
                cls._map_capec_ids(
                    raw.get(
                        "RelatedAttackPatterns"
                    )
                )
            ),
            catalog_version=(
                cls._optional_text(
                    catalog_version,
                    field_name=(
                        "catalog_version"
                    ),
                )
            ),
            catalog_date=(
                cls._optional_text(
                    catalog_date,
                    field_name="catalog_date",
                )
            ),
        )

    @classmethod
    def _mapping_collection(
        cls,
        value: Any,
        *,
        field_name: str,
    ) -> tuple[dict[str, Any], ...]:
        if value is None:
            return ()

        if not isinstance(
            value,
            list,
        ):
            raise ValueError(
                f"{field_name} must be a list"
            )

        cls._validate_collection_size(
            value,
            field_name=field_name,
        )

        normalized: list[
            dict[str, Any]
        ] = []

        for item in value:
            if not isinstance(
                item,
                Mapping,
            ):
                raise ValueError(
                    f"{field_name} must contain "
                    "mapping elements"
                )

            normalized.append(
                dict(item)
            )

        return tuple(
            normalized
        )

    @classmethod
    def _map_platforms(
        cls,
        value: Any,
    ) -> tuple[dict[str, Any], ...]:
        if value is None:
            return ()

        if not isinstance(
            value,
            Mapping,
        ):
            raise ValueError(
                "ApplicablePlatforms must "
                "be a mapping"
            )

        normalized: list[
            dict[str, Any]
        ] = []

        for platform_type, items in value.items():
            if not isinstance(
                platform_type,
                str,
            ):
                raise ValueError(
                    "ApplicablePlatforms keys "
                    "must be strings"
                )

            if not isinstance(
                items,
                list,
            ):
                raise ValueError(
                    "ApplicablePlatforms values "
                    "must be lists"
                )

            cls._validate_collection_size(
                items,
                field_name=(
                    "ApplicablePlatforms."
                    f"{platform_type}"
                ),
            )

            for item in items:
                if not isinstance(
                    item,
                    Mapping,
                ):
                    raise ValueError(
                        "ApplicablePlatforms lists "
                        "must contain mappings"
                    )

                normalized.append(
                    {
                        "type": platform_type,
                        **dict(item),
                    }
                )

        cls._validate_collection_size(
            normalized,
            field_name="ApplicablePlatforms",
        )

        return tuple(
            normalized
        )

    @classmethod
    def _map_alternate_terms(
        cls,
        value: Any,
    ) -> tuple[str, ...]:
        if value is None:
            return ()

        if not isinstance(
            value,
            list,
        ):
            raise ValueError(
                "AlternateTerms must be a list"
            )

        cls._validate_collection_size(
            value,
            field_name="AlternateTerms",
        )

        normalized: list[str] = []

        for item in value:
            if isinstance(
                item,
                str,
            ):
                term = cls._optional_text(
                    item,
                    field_name=(
                        "AlternateTerms"
                    ),
                )

            elif isinstance(
                item,
                Mapping,
            ):
                term = cls._optional_text(
                    item.get("Term"),
                    field_name=(
                        "AlternateTerms.Term"
                    ),
                )

            else:
                raise ValueError(
                    "AlternateTerms elements "
                    "must be strings or mappings"
                )

            if term is not None:
                normalized.append(
                    term
                )

        return tuple(
            dict.fromkeys(
                normalized
            )
        )

    @classmethod
    def _map_capec_ids(
        cls,
        value: Any,
    ) -> tuple[str, ...]:
        if value is None:
            return ()

        if not isinstance(
            value,
            list,
        ):
            raise ValueError(
                "RelatedAttackPatterns must "
                "be a list"
            )

        cls._validate_collection_size(
            value,
            field_name=(
                "RelatedAttackPatterns"
            ),
        )

        normalized: list[str] = []

        for item in value:
            if not isinstance(
                item,
                Mapping,
            ):
                raise ValueError(
                    "RelatedAttackPatterns must "
                    "contain mappings"
                )

            raw_id = (
                item.get("CAPECID")
                or item.get("CAPEC_ID")
                or item.get("CapecID")
            )

            if raw_id is None:
                continue

            capec_id = (
                cls._normalize_capec_id(
                    raw_id
                )
            )

            normalized.append(
                capec_id
            )

        return tuple(
            dict.fromkeys(
                normalized
            )
        )

    @classmethod
    def _normalize_cwe_id(
        cls,
        value: Any,
    ) -> str:
        if isinstance(
            value,
            bool,
        ):
            raise ValueError(
                "ID must be a valid CWE identifier"
            )

        if isinstance(
            value,
            int,
        ):
            value = str(
                value
            )

        if not isinstance(
            value,
            str,
        ):
            raise ValueError(
                "ID must be a valid CWE identifier"
            )

        match = cls.CWE_ID_PATTERN.fullmatch(
            value.strip()
        )

        if match is None:
            raise ValueError(
                "ID must be a valid CWE identifier"
            )

        return (
            f"CWE-{int(match.group(1))}"
        )

    @classmethod
    def _normalize_capec_id(
        cls,
        value: Any,
    ) -> str:
        if isinstance(
            value,
            bool,
        ):
            raise ValueError(
                "CAPEC identifier is invalid"
            )

        if isinstance(
            value,
            int,
        ):
            value = str(
                value
            )

        if not isinstance(
            value,
            str,
        ):
            raise ValueError(
                "CAPEC identifier is invalid"
            )

        match = (
            cls.CAPEC_ID_PATTERN
            .fullmatch(
                value.strip()
            )
        )

        if match is None:
            raise ValueError(
                "CAPEC identifier is invalid"
            )

        return (
            f"CAPEC-{int(match.group(1))}"
        )

    @classmethod
    def _required_text(
        cls,
        value: Any,
        *,
        field_name: str,
    ) -> str:
        normalized = cls._optional_text(
            value,
            field_name=field_name,
        )

        if normalized is None:
            raise ValueError(
                f"{field_name} must not be empty"
            )

        return normalized

    @classmethod
    def _optional_text(
        cls,
        value: Any,
        *,
        field_name: str,
    ) -> str | None:
        if value is None:
            return None

        if not isinstance(
            value,
            str,
        ):
            raise ValueError(
                f"{field_name} must be a string"
            )

        normalized = value.strip()

        if len(normalized) > (
            cls.MAX_TEXT_LENGTH
        ):
            raise ValueError(
                f"{field_name} exceeds "
                "the maximum allowed size"
            )

        return normalized or None

    @classmethod
    def _validate_collection_size(
        cls,
        values: Iterable[Any],
        *,
        field_name: str,
    ) -> None:
        try:
            size = len(values)  # type: ignore[arg-type]
        except TypeError as error:
            raise TypeError(
                f"{field_name} must be sized"
            ) from error

        if size > cls.MAX_COLLECTION_ITEMS:
            raise ValueError(
                f"{field_name} exceeds "
                "the maximum allowed size"
            )