# domain/weakness_reference.py

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class WeaknessReference:
    """
    Weakness assertion provided by one Threat Intelligence source.

    It preserves the source information and, when possible,
    links it to a canonical CWE identifier.
    """

    # Source that reported the weakness.
    #
    # Examples:
    # NVD, MITRE, CISA, github_advisory
    source: str

    # Canonical CWE identifier after safe normalization.
    #
    # Examples:
    # CWE-79, CWE-89
    #
    # None when the source only provides an unresolved description.
    cwe_id: str | None = None

    # Name or description supplied by the source.
    #
    # This is not necessarily the official catalog name.
    source_description: str | None = None

    # Classification explicitly supplied by the source.
    #
    # Example from MITRE CVE:
    # type="CWE"
    source_type: str | None = None

    # Language of the source description.
    language: str | None = None

    # Where the assertion came from inside the source record.
    #
    # Examples:
    # cna, adp, nvd_primary, github_advisory, cisa_kev
    origin: str | None = None

    # resolved:
    #   A valid canonical CWE identifier is available.
    #
    # unresolved:
    #   Only a textual description is available.
    #
    # placeholder:
    #   NVD-CWE-noinfo or NVD-CWE-Other.
    #
    # invalid:
    #   A malformed identifier was supplied.
    resolution_status: str = "unresolved"

    # explicit_id:
    #   A dedicated cweId/cwe_id field supplied the ID.
    #
    # extracted_id:
    #   The ID was extracted from a combined text.
    #
    # source_placeholder:
    #   The source explicitly reported no usable CWE.
    resolution_method: str | None = None

    # Original source representation for traceability.
    raw: dict[str, Any] = field(
        default_factory=dict,
        repr=False,
        compare=False,
    )