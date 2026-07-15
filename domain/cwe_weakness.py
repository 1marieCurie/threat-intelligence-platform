# domain/cwe_weakness.py

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class CWEWeakness:
    """
    Official normalized entry from the MITRE CWE catalog.
    """

    id: str
    name: str
    description: str

    abstraction: str | None = None
    structure: str | None = None
    status: str | None = None

    extended_description: str | None = None
    likelihood_of_exploit: str | None = None

    mapping_usage: str | None = None
    mapping_rationale: str | None = None

    relationships: tuple[dict[str, Any], ...] = field(
        default_factory=tuple
    )

    consequences: tuple[dict[str, Any], ...] = field(
        default_factory=tuple
    )

    mitigations: tuple[dict[str, Any], ...] = field(
        default_factory=tuple
    )

    detection_methods: tuple[dict[str, Any], ...] = field(
        default_factory=tuple
    )

    applicable_platforms: tuple[dict[str, Any], ...] = field(
        default_factory=tuple
    )

    modes_of_introduction: tuple[dict[str, Any], ...] = field(
        default_factory=tuple
    )

    alternate_terms: tuple[str, ...] = field(
        default_factory=tuple
    )

    related_capec_ids: tuple[str, ...] = field(
        default_factory=tuple
    )

    catalog_version: str | None = None
    catalog_date: str | None = None

    raw: dict[str, Any] = field(
        default_factory=dict,
        repr=False,
        compare=False,
    )