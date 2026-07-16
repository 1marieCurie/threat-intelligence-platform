from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from application.services.mitre_threat_source import (
    MITREThreatSource,
)
from domain.collection_result import CollectionResult
from domain.threat import Threat
from domain.threat_category import ThreatCategory
from domain.weakness_reference import WeaknessReference
from infrastructure.adapters.outbound.mitre_connector import (
    MITREConnector,
)
from infrastructure.persistence.mitre_sync_state import (
    MITRESyncState,
)


FILEPATH = (
    "cves/2026/0xxx/"
    "CVE-2026-0964.json"
)

OLD_COMMIT = (
    "1111111111111111111111111111111111111111"
)

CURRENT_COMMIT = (
    "2222222222222222222222222222222222222222"
)


# ============================================================
# Fake CVE record
# ============================================================


@pytest.fixture
def sample_mitre_record() -> dict[str, Any]:
    """
    Return a realistic MITRE CVE Record compatible with the
    current MITREThreatSource parser.

    The fixture contains:
    - one primary CNA weakness;
    - one ADP weakness enrichment;
    - one CNA CVSS metric;
    - CNA and ADP references;
    - one affected product.
    """

    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.2",
        "cveMetadata": {
            "cveId": "CVE-2026-0964",
            "assignerOrgId": (
                "11111111-2222-3333-4444-555555555555"
            ),
            "state": "PUBLISHED",
            "datePublished": "2026-01-10T10:00:00.000Z",
            "dateUpdated": "2026-01-11T12:00:00.000Z",
        },
        "containers": {
            "cna": {
                "providerMetadata": {
                    "orgId": (
                        "11111111-2222-3333-4444-555555555555"
                    ),
                    "shortName": "ExampleCNA",
                    "dateUpdated": (
                        "2026-01-11T12:00:00.000Z"
                    ),
                },
                "title": (
                    "Example product path sanitization "
                    "vulnerability"
                ),
                "descriptions": [
                    {
                        "lang": "en",
                        "value": (
                            "Example Product contains an improper "
                            "path sanitization vulnerability."
                        ),
                    }
                ],
                "affected": [
                    {
                        "vendor": "Example Vendor",
                        "product": "Example Product",
                        "platforms": [
                            "Linux",
                            "Windows",
                        ],
                        "versions": [
                            {
                                "version": "1.0.0",
                                "status": "affected",
                            },
                            {
                                "version": "2.0.0",
                                "status": "unaffected",
                            },
                        ],
                        "cpes": [
                            (
                                "cpe:2.3:a:example_vendor:"
                                "example_product:1.0.0:*:*:*:*:*:*:*"
                            )
                        ],
                    }
                ],
                "problemTypes": [
                    {
                        "descriptions": [
                            {
                                "lang": "en",
                                "cweId": "CWE-22",
                                "description": (
                                    "Improper Limitation of a "
                                    "Pathname to a Restricted "
                                    "Directory"
                                ),
                                "type": "CWE",
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": (
                            "https://example.org/advisories/"
                            "CVE-2026-0964"
                        ),
                    },
                    {
                        "url": (
                            "https://example.org/patches/"
                            "CVE-2026-0964"
                        ),
                    },
                ],
                "tags": [
                    "disputed",
                ],
                "solutions": [
                    {
                        "lang": "en",
                        "value": (
                            "Upgrade Example Product to version "
                            "2.0.0 or later."
                        ),
                    }
                ],
                "metrics": [
                    {
                        "cvssV3_1": {
                            "version": "3.1",
                            "vectorString": (
                                "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/"
                                "S:U/C:L/I:L/A:L"
                            ),
                            "baseScore": 6.3,
                            "baseSeverity": "MEDIUM",
                        }
                    }
                ],
            },
            "adp": [
                {
                    "providerMetadata": {
                        "orgId": (
                            "22222222-3333-4444-5555-"
                            "666666666666"
                        ),
                        "shortName": "ExampleADP",
                        "dateUpdated": (
                            "2026-01-12T12:00:00.000Z"
                        ),
                    },
                    "references": [
                        {
                            "url": (
                                "https://example.org/"
                                "additional-analysis"
                            ),
                        }
                    ],
                    "tags": [
                        "adp-enriched",
                    ],
                    "problemTypes": [
                        {
                            "descriptions": [
                                {
                                    "lang": "en",
                                    "cweId": "CWE-22",
                                    "description": (
                                        "Path traversal"
                                    ),
                                    "type": "CWE",
                                }
                            ]
                        }
                    ],
                }
            ],
        },
    }


# ============================================================
# Fake connector
# ============================================================


class FakeMITREConnector(MITREConnector):
    """
    Deterministic replacement for MITREConnector.

    No HTTP request is performed.
    """

    def __init__(
        self,
        records: list[dict[str, Any]],
        current_commit: str = CURRENT_COMMIT,
    ) -> None:
        # The fake does not need a requests.Session.
        self.records = deepcopy(records)
        self.current_commit = current_commit

        self.fetch_new_records_calls = 0
        self.download_calls = 0
        self.latest_commit_calls = 0

    def get_latest_commit(self) -> str:
        self.latest_commit_calls += 1

        return self.current_commit

    def download_cve_record(
        self,
        filepath: str,
    ) -> dict[str, Any]:
        self.download_calls += 1

        if not self.records:
            raise ValueError(
                "No fake MITRE record is configured."
            )

        return deepcopy(self.records[0])

    def fetch_new_records(
        self,
        old_commit: str | None,
    ) -> tuple[str, list[dict[str, Any]]]:
        self.fetch_new_records_calls += 1

        if old_commit == self.current_commit:
            return self.current_commit, []

        return (
            self.current_commit,
            deepcopy(self.records),
        )


# ============================================================
# Source builder
# ============================================================


def _build_source(
    tmp_path: Path,
    records: list[dict[str, Any]],
    current_commit: str = CURRENT_COMMIT,
) -> tuple[MITREThreatSource, FakeMITREConnector]:
    """
    Build MITREThreatSource with temporary persistence and a fake
    connector.
    """

    sync_file = (
        tmp_path
        / "mitre_sync_state.json"
    )

    sync_state = MITRESyncState(
        filepath=str(sync_file)
    )

    fake_connector = FakeMITREConnector(
        records=records,
        current_commit=current_commit,
    )

    source = MITREThreatSource(
        connector=fake_connector,
        sync_state=sync_state,
    )

    return source, fake_connector


# ============================================================
# Unit tests: basic parsing
# ============================================================


def test_source_name(
    tmp_path: Path,
) -> None:
    source, _ = _build_source(
        tmp_path,
        [],
    )

    assert source.name() == "MITRE"


def test_parse_single_record(
    tmp_path: Path,
    sample_mitre_record: dict[str, Any],
) -> None:
    """
    Verify complete mapping of one MITRE CVE record.
    """

    source, _ = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    threats = source.parse(
        [deepcopy(sample_mitre_record)]
    )

    assert len(threats) == 1

    threat = threats[0]

    print(
        "\n[MITRE SERVICE] "
        "Successfully parsed one fake CVE Record"
    )
    print(f"CVE ID       : {threat.id}")
    print(f"Source       : {threat.source}")
    print(f"Title        : {threat.title}")
    print(f"Severity     : {threat.severity}")
    print(f"CVSS Score   : {threat.cvss_score}")
    print(
        "Weakness refs: "
        f"{len(threat.weakness_references)}"
    )
    print(f"References   : {len(threat.references)}")
    print(
        "Products     : "
        f"{len(threat.affected_products)}"
    )

    assert isinstance(threat, Threat)

    # Identity
    assert threat.id == "CVE-2026-0964"
    assert threat.source == "MITRE"
    assert threat.category is ThreatCategory.VULNERABILITY

    # Main fields
    assert threat.title == (
        "Example product path sanitization "
        "vulnerability"
    )

    assert threat.description == (
        "Example Product contains an improper "
        "path sanitization vulnerability."
    )

    assert threat.severity == "MEDIUM"
    assert threat.cvss_score == 6.3

    # Dates
    assert threat.published_date == (
        "2026-01-10T10:00:00.000Z"
    )

    assert threat.last_modified_date == (
        "2026-01-11T12:00:00.000Z"
    )

    # Products
    assert len(threat.affected_products) == 1

    assert threat.affected_products[0] == {
        "vendor": "Example Vendor",
        "product": "Example Product",
        "versions": [
            {
                "version": "1.0.0",
                "status": "affected",
            },
            {
                "version": "2.0.0",
                "status": "unaffected",
            },
        ],
        "platforms": [
            "Linux",
            "Windows",
        ],
        "cpes": [
            (
                "cpe:2.3:a:example_vendor:"
                "example_product:1.0.0:*:*:*:*:*:*:*"
            )
        ],
    }

    # References: CNA + ADP
    assert threat.references == [
        (
            "https://example.org/advisories/"
            "CVE-2026-0964"
        ),
        (
            "https://example.org/patches/"
            "CVE-2026-0964"
        ),
        "https://example.org/additional-analysis",
    ]

    # Labels: CNA + ADP
    assert threat.labels == [
        "disputed",
        "adp-enriched",
    ]

    # Remediation
    assert threat.remediation == (
        "Upgrade Example Product to version "
        "2.0.0 or later."
    )

    # CWE references: CNA + ADP
    assert isinstance(
        threat.weakness_references,
        list,
    )

    assert len(threat.weakness_references) == 2

    cna_reference = (
        threat.weakness_references[0]
    )

    adp_reference = (
        threat.weakness_references[1]
    )

    assert isinstance(
        cna_reference,
        WeaknessReference,
    )

    assert isinstance(
        adp_reference,
        WeaknessReference,
    )

    assert cna_reference.source == "MITRE"
    assert cna_reference.cwe_id == "CWE-22"

    assert cna_reference.source_description == (
        "Improper Limitation of a Pathname "
        "to a Restricted Directory"
    )

    assert cna_reference.source_type == "CWE"
    assert cna_reference.language == "en"
    assert cna_reference.origin == "cna"

    assert (
        cna_reference.resolution_status
        == "resolved"
    )

    assert (
        cna_reference.resolution_method
        == "explicit_id"
    )

    assert adp_reference.source == "MITRE"
    assert adp_reference.cwe_id == "CWE-22"
    assert adp_reference.source_description == (
        "Path traversal"
    )
    assert adp_reference.origin == "adp"

    assert (
        adp_reference.resolution_status
        == "resolved"
    )

    assert (
        adp_reference.resolution_method
        == "explicit_id"
    )

    # Raw record preservation
    assert threat.raw == sample_mitre_record


def test_parse_multiple_records(
    tmp_path: Path,
    sample_mitre_record: dict[str, Any],
) -> None:
    source, _ = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    second_record = deepcopy(
        sample_mitre_record
    )

    second_record["cveMetadata"]["cveId"] = (
        "CVE-2026-9999"
    )

    threats = source.parse(
        [
            deepcopy(sample_mitre_record),
            second_record,
        ]
    )

    assert len(threats) == 2

    assert [
        threat.id
        for threat in threats
    ] == [
        "CVE-2026-0964",
        "CVE-2026-9999",
    ]


def test_parse_empty_list(
    tmp_path: Path,
) -> None:
    source, _ = _build_source(
        tmp_path,
        [],
    )

    assert source.parse([]) == []


def test_parse_invalid_raw_data(
    tmp_path: Path,
) -> None:
    """
    Invalid top-level values must produce an empty list.
    """

    source, _ = _build_source(
        tmp_path,
        [],
    )

    assert source.parse(None) == []
    assert source.parse({}) == []
    assert source.parse("invalid") == []


def test_parse_ignores_invalid_record_elements(
    tmp_path: Path,
    sample_mitre_record: dict[str, Any],
) -> None:
    source, _ = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    records: list[Any] = [
        None,
        "invalid",
        123,
        [],
        deepcopy(sample_mitre_record),
    ]

    threats = source.parse(records)

    assert len(threats) == 1
    assert threats[0].id == "CVE-2026-0964"


def test_missing_cve_identifier_raises_value_error(
    tmp_path: Path,
    sample_mitre_record: dict[str, Any],
) -> None:
    source, _ = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    record = deepcopy(
        sample_mitre_record
    )

    record["cveMetadata"].pop(
        "cveId",
        None,
    )

    with pytest.raises(
        ValueError,
        match="Missing CVE identifier",
    ):
        source._parse_record(record)


def test_empty_cve_identifier_raises_value_error(
    tmp_path: Path,
    sample_mitre_record: dict[str, Any],
) -> None:
    source, _ = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    record = deepcopy(
        sample_mitre_record
    )

    record["cveMetadata"]["cveId"] = "   "

    with pytest.raises(
        ValueError,
        match="Missing CVE identifier",
    ):
        source._parse_record(record)


# ============================================================
# Description tests
# ============================================================


def test_description_prefers_english(
    tmp_path: Path,
    sample_mitre_record: dict[str, Any],
) -> None:
    source, _ = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    record = deepcopy(
        sample_mitre_record
    )

    cna = record["containers"]["cna"]

    cna["descriptions"] = [
        {
            "lang": "fr",
            "value": "Description française.",
        },
        {
            "lang": "en",
            "value": "English description.",
        },
    ]

    threat = source._parse_record(record)

    assert threat.description == (
        "English description."
    )


def test_description_falls_back_to_first_language(
    tmp_path: Path,
    sample_mitre_record: dict[str, Any],
) -> None:
    source, _ = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    record = deepcopy(
        sample_mitre_record
    )

    record["containers"]["cna"]["descriptions"] = [
        {
            "lang": "fr",
            "value": "Description française.",
        },
        {
            "lang": "es",
            "value": "Descripción española.",
        },
    ]

    threat = source._parse_record(record)

    assert threat.description == (
        "Description française."
    )


def test_description_replaces_non_breaking_spaces(
    tmp_path: Path,
    sample_mitre_record: dict[str, Any],
) -> None:
    source, _ = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    record = deepcopy(
        sample_mitre_record
    )

    record["containers"]["cna"]["descriptions"] = [
        {
            "lang": "en",
            "value": (
                "Example\u00a0description\u00a0text."
            ),
        }
    ]

    threat = source._parse_record(record)

    assert threat.description == (
        "Example description text."
    )


def test_missing_descriptions_returns_empty_string(
    tmp_path: Path,
    sample_mitre_record: dict[str, Any],
) -> None:
    source, _ = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    record = deepcopy(
        sample_mitre_record
    )

    record["containers"]["cna"].pop(
        "descriptions",
        None,
    )

    threat = source._parse_record(record)

    assert threat.description == ""


# ============================================================
# CWE WeaknessReference tests
# ============================================================


def test_extract_explicit_cwe_reference(
    tmp_path: Path,
    sample_mitre_record: dict[str, Any],
) -> None:
    source, _ = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    cna = deepcopy(
        sample_mitre_record["containers"]["cna"]
    )

    references = (
        source._extract_weakness_references(
            cna,
            origin="cna",
        )
    )

    assert len(references) == 1

    reference = references[0]

    assert isinstance(
        reference,
        WeaknessReference,
    )

    assert reference.source == "MITRE"
    assert reference.cwe_id == "CWE-22"
    assert reference.origin == "cna"

    assert (
        reference.resolution_status
        == "resolved"
    )

    assert (
        reference.resolution_method
        == "explicit_id"
    )


def test_extract_cwe_from_description_only(
    tmp_path: Path,
    sample_mitre_record: dict[str, Any],
) -> None:
    source, _ = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    cna = deepcopy(
        sample_mitre_record["containers"]["cna"]
    )

    description = (
        cna["problemTypes"][0]
        ["descriptions"][0]
    )

    description.pop("cweId", None)
    description["description"] = "CWE-79"

    references = (
        source._extract_weakness_references(
            cna,
            origin="cna",
        )
    )

    assert len(references) == 1
    assert references[0].cwe_id == "CWE-79"

    assert (
        references[0].resolution_status
        == "resolved"
    )

    assert (
        references[0].resolution_method
        == "explicit_id"
    )


def test_extract_cwe_from_combined_description(
    tmp_path: Path,
    sample_mitre_record: dict[str, Any],
) -> None:
    source, _ = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    cna = deepcopy(
        sample_mitre_record["containers"]["cna"]
    )

    description = (
        cna["problemTypes"][0]
        ["descriptions"][0]
    )

    description.pop("cweId", None)

    description["description"] = (
        "CWE-79: Improper Neutralization of Input"
    )

    references = (
        source._extract_weakness_references(
            cna,
            origin="cna",
        )
    )

    assert len(references) == 1
    assert references[0].cwe_id == "CWE-79"

    assert (
        references[0].resolution_method
        == "extracted_id"
    )


def test_extract_unresolved_weakness_description(
    tmp_path: Path,
    sample_mitre_record: dict[str, Any],
) -> None:
    source, _ = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    cna = deepcopy(
        sample_mitre_record["containers"]["cna"]
    )

    description = (
        cna["problemTypes"][0]
        ["descriptions"][0]
    )

    description.pop("cweId", None)

    description["description"] = (
        "Improper path validation"
    )

    references = (
        source._extract_weakness_references(
            cna,
            origin="cna",
        )
    )

    assert len(references) == 1

    reference = references[0]

    assert reference.cwe_id is None

    assert (
        reference.resolution_status
        == "unresolved"
    )

    assert reference.resolution_method is None


@pytest.mark.parametrize(
    "placeholder",
    [
        "NVD-CWE-noinfo",
        "NVD-CWE-Other",
        "CWE-noinfo",
        "CWE-Other",
    ],
)
def test_extract_cwe_placeholder_from_description(
    tmp_path: Path,
    sample_mitre_record: dict[str, Any],
    placeholder: str,
) -> None:
    source, _ = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    cna = deepcopy(
        sample_mitre_record["containers"]["cna"]
    )

    description = (
        cna["problemTypes"][0]
        ["descriptions"][0]
    )

    description.pop("cweId", None)
    description["description"] = placeholder

    references = (
        source._extract_weakness_references(
            cna,
            origin="cna",
        )
    )

    assert len(references) == 1

    reference = references[0]

    assert reference.cwe_id is None

    assert (
        reference.resolution_status
        == "placeholder"
    )

    assert (
        reference.resolution_method
        == "source_placeholder"
    )


def test_extract_invalid_explicit_cwe_id(
    tmp_path: Path,
    sample_mitre_record: dict[str, Any],
) -> None:
    source, _ = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    cna = deepcopy(
        sample_mitre_record["containers"]["cna"]
    )

    description = (
        cna["problemTypes"][0]
        ["descriptions"][0]
    )

    description["cweId"] = "CWE-ABC"

    references = (
        source._extract_weakness_references(
            cna,
            origin="cna",
        )
    )

    assert len(references) == 1

    reference = references[0]

    assert reference.cwe_id is None

    assert (
        reference.resolution_status
        == "invalid"
    )

    assert reference.resolution_method is None


def test_weakness_references_remove_duplicates(
    tmp_path: Path,
    sample_mitre_record: dict[str, Any],
) -> None:
    source, _ = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    cna = deepcopy(
        sample_mitre_record["containers"]["cna"]
    )

    duplicate = deepcopy(
        cna["problemTypes"][0]
        ["descriptions"][0]
    )

    cna["problemTypes"][0][
        "descriptions"
    ].append(duplicate)

    references = (
        source._extract_weakness_references(
            cna,
            origin="cna",
        )
    )

    assert len(references) == 1
    assert references[0].cwe_id == "CWE-22"


def test_weakness_extraction_ignores_invalid_elements(
    tmp_path: Path,
) -> None:
    source, _ = _build_source(
        tmp_path,
        [],
    )

    container = {
        "problemTypes": [
            None,
            "invalid",
            {
                "descriptions": None,
            },
            {
                "descriptions": [
                    None,
                    "invalid",
                    {},
                    {
                        "lang": "en",
                        "cweId": "CWE-89",
                        "description": (
                            "SQL Injection"
                        ),
                        "type": "CWE",
                    },
                ]
            },
        ]
    }

    references = (
        source._extract_weakness_references(
            container,
            origin="cna",
        )
    )

    assert len(references) == 1
    assert references[0].cwe_id == "CWE-89"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("CWE-22", "CWE-22"),
        ("cwe-22", "CWE-22"),
        ("22", "CWE-22"),
        (22, "CWE-22"),
        ("CWE-00022", "CWE-22"),
        ("0", None),
        (0, None),
        (-1, None),
        (True, None),
        ("CWE-ABC", None),
        ("", None),
        (None, None),
    ],
)
def test_normalize_cwe_id(
    value: Any,
    expected: str | None,
) -> None:
    assert (
        MITREThreatSource._normalize_cwe_id(
            value
        )
        == expected
    )


# ============================================================
# ADP enrichment tests
# ============================================================


def test_adp_enrichment(
    tmp_path: Path,
    sample_mitre_record: dict[str, Any],
) -> None:
    source, _ = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    threat = source.parse(
        [deepcopy(sample_mitre_record)]
    )[0]

    print(
        "\n[MITRE SERVICE] "
        "ADP enrichment verification"
    )
    print(f"References : {len(threat.references)}")
    print(
        "Weaknesses : "
        f"{len(threat.weakness_references)}"
    )
    print(f"Labels     : {len(threat.labels)}")

    assert (
        "https://example.org/additional-analysis"
        in threat.references
    )

    assert "adp-enriched" in threat.labels

    assert any(
        reference.origin == "adp"
        and reference.cwe_id == "CWE-22"
        and reference.source_description
        == "Path traversal"
        for reference
        in threat.weakness_references
    )


def test_adp_supplies_cvss_when_cna_has_none(
    tmp_path: Path,
    sample_mitre_record: dict[str, Any],
) -> None:
    source, _ = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    record = deepcopy(
        sample_mitre_record
    )

    cna = record["containers"]["cna"]
    adp = record["containers"]["adp"][0]

    cna.pop("metrics", None)

    adp["metrics"] = [
        {
            "cvssV3_1": {
                "version": "3.1",
                "baseScore": 8.8,
                "baseSeverity": "HIGH",
            }
        }
    ]

    threat = source._parse_record(record)

    assert threat.cvss_score == 8.8
    assert threat.severity == "HIGH"


def test_adp_does_not_replace_cna_cvss(
    tmp_path: Path,
    sample_mitre_record: dict[str, Any],
) -> None:
    source, _ = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    record = deepcopy(
        sample_mitre_record
    )

    record["containers"]["adp"][0][
        "metrics"
    ] = [
        {
            "cvssV3_1": {
                "version": "3.1",
                "baseScore": 9.8,
                "baseSeverity": "CRITICAL",
            }
        }
    ]

    threat = source._parse_record(record)

    assert threat.cvss_score == 6.3
    assert threat.severity == "MEDIUM"


def test_adp_supplies_remediation_when_cna_has_none(
    tmp_path: Path,
    sample_mitre_record: dict[str, Any],
) -> None:
    source, _ = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    record = deepcopy(
        sample_mitre_record
    )

    cna = record["containers"]["cna"]
    adp = record["containers"]["adp"][0]

    cna.pop("solutions", None)
    cna.pop("workarounds", None)

    adp["solutions"] = [
        {
            "lang": "en",
            "value": "Apply the ADP-provided patch.",
        }
    ]

    threat = source._parse_record(record)

    assert threat.remediation == (
        "Apply the ADP-provided patch."
    )


def test_invalid_adp_elements_are_ignored(
    tmp_path: Path,
    sample_mitre_record: dict[str, Any],
) -> None:
    source, _ = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    record = deepcopy(
        sample_mitre_record
    )

    record["containers"]["adp"] = [
        None,
        "invalid",
        123,
        record["containers"]["adp"][0],
    ]

    threat = source._parse_record(record)

    assert isinstance(threat, Threat)

    assert (
        "https://example.org/additional-analysis"
        in threat.references
    )


# ============================================================
# References, labels, products and remediation
# ============================================================


def test_references_remove_duplicates(
    tmp_path: Path,
    sample_mitre_record: dict[str, Any],
) -> None:
    source, _ = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    cna = deepcopy(
        sample_mitre_record["containers"]["cna"]
    )

    cna["references"].append(
        deepcopy(cna["references"][0])
    )

    references = source._extract_references(
        cna
    )

    assert references == [
        (
            "https://example.org/advisories/"
            "CVE-2026-0964"
        ),
        (
            "https://example.org/patches/"
            "CVE-2026-0964"
        ),
    ]


def test_invalid_references_are_ignored(
    tmp_path: Path,
) -> None:
    source, _ = _build_source(
        tmp_path,
        [],
    )

    container = {
        "references": [
            None,
            "invalid",
            {},
            {
                "url": None,
            },
            {
                "url": "   ",
            },
            {
                "url": "https://example.org/valid",
            },
        ]
    }

    assert source._extract_references(
        container
    ) == [
        "https://example.org/valid",
    ]


def test_invalid_labels_are_ignored(
    tmp_path: Path,
) -> None:
    source, _ = _build_source(
        tmp_path,
        [],
    )

    container = {
        "tags": [
            None,
            123,
            "",
            "   ",
            "valid-tag",
            "valid-tag",
        ]
    }

    assert source._extract_labels(
        container
    ) == [
        "valid-tag",
    ]


def test_missing_affected_products_returns_empty_list(
    tmp_path: Path,
    sample_mitre_record: dict[str, Any],
) -> None:
    source, _ = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    record = deepcopy(
        sample_mitre_record
    )

    record["containers"]["cna"].pop(
        "affected",
        None,
    )

    threat = source._parse_record(record)

    assert threat.affected_products == []


def test_solutions_preferred_over_workarounds(
    tmp_path: Path,
) -> None:
    source, _ = _build_source(
        tmp_path,
        [],
    )

    container = {
        "solutions": [
            {
                "value": "Apply the patch.",
            }
        ],
        "workarounds": [
            {
                "value": "Disable the feature.",
            }
        ],
    }

    assert source._extract_remediation(
        container
    ) == "Apply the patch."


def test_workaround_used_when_solution_missing(
    tmp_path: Path,
) -> None:
    source, _ = _build_source(
        tmp_path,
        [],
    )

    container = {
        "workarounds": [
            {
                "value": "Disable the affected feature.",
            }
        ]
    }

    assert source._extract_remediation(
        container
    ) == (
        "Disable the affected feature."
    )


# ============================================================
# Unit tests: synchronization and collection
# ============================================================


def test_fetch_raw_with_fake_connector(
    tmp_path: Path,
    sample_mitre_record: dict[str, Any],
) -> None:
    source, fake_connector = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    raw = source.fetch_raw()

    print(
        "\n[MITRE SERVICE] "
        "fetch_raw() with fake connector"
    )
    print(
        "Previous commit : "
        f"{raw['previous_commit']}"
    )
    print(
        "Current commit  : "
        f"{raw['current_commit']}"
    )
    print(
        "Records fetched : "
        f"{len(raw['records'])}"
    )

    assert raw["previous_commit"] is None
    assert raw["current_commit"] == CURRENT_COMMIT
    assert len(raw["records"]) == 1

    assert (
        fake_connector.fetch_new_records_calls
        == 1
    )


def test_collect_returns_collection_result(
    tmp_path: Path,
    sample_mitre_record: dict[str, Any],
) -> None:
    source, _ = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    result = source.collect()

    assert isinstance(
        result,
        CollectionResult,
    )

    assert len(result.threats) == 1
    assert isinstance(
        result.threats[0],
        Threat,
    )


def test_collect_metadata(
    tmp_path: Path,
    sample_mitre_record: dict[str, Any],
) -> None:
    source, _ = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    result = source.collect()

    print(
        "\n[MITRE SERVICE] Collection metadata"
    )

    for key, value in result.metadata.items():
        print(f"{key}: {value}")

    assert (
        result.metadata["source"]
        == "MITRE"
    )

    assert (
        result.metadata["category"]
        == ThreatCategory.VULNERABILITY.value
    )

    assert (
        result.metadata["previous_commit"]
        is None
    )

    assert (
        result.metadata["current_commit"]
        == CURRENT_COMMIT
    )

    assert (
        result.metadata["records_collected"]
        == 1
    )


def test_incremental_synchronization(
    tmp_path: Path,
    sample_mitre_record: dict[str, Any],
) -> None:
    """
    Simulate synchronization from an old commit without GitHub.
    """

    source, fake_connector = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    source.sync_state.save_last_commit(
        OLD_COMMIT
    )

    result = source.collect()

    assert (
        result.metadata["previous_commit"]
        == OLD_COMMIT
    )

    assert (
        result.metadata["current_commit"]
        == CURRENT_COMMIT
    )

    assert (
        result.metadata["previous_commit"]
        != result.metadata["current_commit"]
    )

    assert len(result.threats) == 1

    assert (
        fake_connector.fetch_new_records_calls
        == 1
    )


def test_commit_state_updated(
    tmp_path: Path,
    sample_mitre_record: dict[str, Any],
) -> None:
    source, _ = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    result = source.collect()

    saved_commit = (
        source.sync_state.get_last_commit()
    )

    assert saved_commit == CURRENT_COMMIT

    assert (
        saved_commit
        == result.metadata["current_commit"]
    )


def test_second_synchronization_returns_no_records(
    tmp_path: Path,
    sample_mitre_record: dict[str, Any],
) -> None:
    source, fake_connector = _build_source(
        tmp_path,
        [sample_mitre_record],
    )

    first = source.collect()
    second = source.collect()

    assert len(first.threats) == 1
    assert len(second.threats) == 0

    assert (
        second.metadata["previous_commit"]
        == CURRENT_COMMIT
    )

    assert (
        second.metadata["current_commit"]
        == CURRENT_COMMIT
    )

    assert (
        fake_connector.fetch_new_records_calls
        == 2
    )


def test_all_threats_have_valid_identifier(
    tmp_path: Path,
    sample_mitre_record: dict[str, Any],
) -> None:
    second_record = deepcopy(
        sample_mitre_record
    )

    second_record["cveMetadata"]["cveId"] = (
        "CVE-2026-9999"
    )

    source, _ = _build_source(
        tmp_path,
        [
            sample_mitre_record,
            second_record,
        ],
    )

    result = source.collect()

    assert len(result.threats) == 2

    for threat in result.threats:
        assert isinstance(threat.id, str)
        assert threat.id.startswith("CVE-")
        assert threat.source == "MITRE"


def test_empty_fake_collection(
    tmp_path: Path,
) -> None:
    source, _ = _build_source(
        tmp_path,
        [],
    )

    result = source.collect()

    assert isinstance(
        result,
        CollectionResult,
    )

    assert result.threats == []

    assert (
        result.metadata["records_collected"]
        == 0
    )


# ============================================================
# Integration tests: real GitHub / MITRE repository
# ============================================================


@pytest.mark.integration
def test_integration_download_and_parse_record(
    tmp_path: Path,
) -> None:
    """
    Download one real CVE record and verify service parsing.
    """

    sync_file = (
        tmp_path
        / "mitre_sync_state.json"
    )

    source = MITREThreatSource(
        sync_state=MITRESyncState(
            filepath=str(sync_file)
        )
    )

    record = (
        source.connector.download_cve_record(
            FILEPATH
        )
    )

    threats = source.parse([record])

    assert len(threats) == 1

    threat = threats[0]

    print(
        "\n[MITRE SERVICE] "
        "Real CVE record parsed"
    )
    print(f"CVE ID      : {threat.id}")
    print(
        "CWE refs    : "
        f"{len(threat.weakness_references)}"
    )

    assert isinstance(threat, Threat)
    assert threat.id == "CVE-2026-0964"
    assert threat.source == "MITRE"
    assert threat.description != ""

    assert isinstance(
        threat.weakness_references,
        list,
    )

    for reference in threat.weakness_references:
        assert isinstance(
            reference,
            WeaknessReference,
        )

        assert reference.source == "MITRE"

        assert reference.origin in {
            "cna",
            "adp",
        }


@pytest.mark.integration
def test_integration_fetch_raw(
    tmp_path: Path,
) -> None:
    """
    Verify real incremental fetching from GitHub.

    A temporary synchronization file protects the project's real
    synchronization state.
    """

    sync_file = (
        tmp_path
        / "mitre_sync_state.json"
    )

    source = MITREThreatSource(
        sync_state=MITRESyncState(
            filepath=str(sync_file)
        )
    )

    raw = source.fetch_raw()

    print(
        "\n[MITRE SERVICE] "
        "Real fetch_raw() execution"
    )
    print(
        "Previous commit : "
        f"{raw['previous_commit']}"
    )
    print(
        "Current commit  : "
        f"{raw['current_commit']}"
    )
    print(
        "Records fetched : "
        f"{len(raw['records'])}"
    )

    assert "previous_commit" in raw
    assert "current_commit" in raw
    assert "records" in raw

    assert raw["current_commit"] is not None
    assert isinstance(
        raw["current_commit"],
        str,
    )

    assert isinstance(
        raw["records"],
        list,
    )

