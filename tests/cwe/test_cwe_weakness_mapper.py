from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from application.services.cwe_weakness_mapper import (
    CWEWeaknessMapper,
)


def _complete_raw_weakness(
) -> dict[str, Any]:
    return {
        "ID": "079",
        "Name": "Cross-site Scripting",
        "Description": (
            "The product does not correctly "
            "neutralize web output."
        ),
        "Abstraction": "Base",
        "Structure": "Simple",
        "Status": "Stable",
        "ExtendedDescription": (
            "Extended CWE description."
        ),
        "LikelihoodOfExploit": "High",
        "MappingNotes": {
            "Usage": "Allowed",
            "Rationale": "Direct mapping",
        },
        "RelatedWeaknesses": [
            {
                "Nature": "ChildOf",
                "CweID": "74",
                "ViewID": "1000",
            },
        ],
        "CommonConsequences": [
            {
                "Scope": [
                    "Confidentiality",
                ],
                "Impact": [
                    "Read Application Data",
                ],
            },
        ],
        "PotentialMitigations": [
            {
                "Phase": [
                    "Implementation",
                ],
                "Description": (
                    "Encode output."
                ),
            },
        ],
        "DetectionMethods": [
            {
                "Method": (
                    "Automated Static Analysis"
                ),
            },
        ],
        "ApplicablePlatforms": {
            "Languages": [
                {
                    "Name": "JavaScript",
                    "Prevalence": "Often",
                },
            ],
            "OperatingSystems": [
                {
                    "Class": "OS-Independent",
                },
            ],
        },
        "ModesOfIntroduction": [
            {
                "Phase": "Implementation",
            },
        ],
        "AlternateTerms": [
            {
                "Term": "XSS",
            },
            "Cross Site Scripting",
            {
                "Term": "XSS",
            },
        ],
        "RelatedAttackPatterns": [
            {
                "CAPECID": "63",
            },
            {
                "CAPEC_ID": "CAPEC-00063",
            },
        ],
    }


def test_map_complete_weakness(
) -> None:
    result = (
        CWEWeaknessMapper.map_weakness(
            _complete_raw_weakness(),
            catalog_version="4.20",
            catalog_date="2026-04-30",
        )
    )

    assert result.id == "CWE-79"
    assert result.name == (
        "Cross-site Scripting"
    )
    assert result.abstraction == "Base"
    assert result.mapping_usage == "Allowed"
    assert result.mapping_rationale == (
        "Direct mapping"
    )

    assert result.relationships == (
        {
            "Nature": "ChildOf",
            "CweID": "74",
            "ViewID": "1000",
        },
    )

    assert result.applicable_platforms == (
        {
            "type": "Languages",
            "Name": "JavaScript",
            "Prevalence": "Often",
        },
        {
            "type": "OperatingSystems",
            "Class": "OS-Independent",
        },
    )

    assert result.alternate_terms == (
        "XSS",
        "Cross Site Scripting",
    )

    assert result.related_capec_ids == (
        "CAPEC-63",
    )

    assert result.catalog_version == "4.20"
    assert result.catalog_date == "2026-04-30"
    assert result.raw == {}


def test_map_payload_maps_and_deduplicates(
) -> None:
    raw = _complete_raw_weakness()

    result = CWEWeaknessMapper.map_payload(
        {
            "Weaknesses": [
                raw,
                deepcopy(raw),
            ],
        },
        catalog_version="4.20",
        catalog_date="2026-04-30",
    )

    assert len(result) == 1
    assert result[0].id == "CWE-79"


def test_map_payload_rejects_conflicting_duplicate(
) -> None:
    first = _complete_raw_weakness()
    second = deepcopy(first)

    second["ID"] = "CWE-00079"
    second["Name"] = "Different name"

    with pytest.raises(
        ValueError,
        match="Conflicting duplicate CWE entry",
    ):
        CWEWeaknessMapper.map_payload(
            {
                "Weaknesses": [
                    first,
                    second,
                ],
            }
        )


def test_optional_fields_can_be_missing(
) -> None:
    result = (
        CWEWeaknessMapper.map_weakness(
            {
                "ID": "89",
                "Name": "SQL Injection",
                "Description": (
                    "SQL command construction "
                    "uses untrusted input."
                ),
            }
        )
    )

    assert result.id == "CWE-89"
    assert result.relationships == ()
    assert result.consequences == ()
    assert result.applicable_platforms == ()
    assert result.alternate_terms == ()
    assert result.related_capec_ids == ()


@pytest.mark.parametrize(
    "invalid_id",
    [
        None,
        "",
        "CWE-0",
        "CVE-2026-1234",
        "CWE-invalid",
        True,
    ],
)
def test_invalid_cwe_id_is_rejected(
    invalid_id: Any,
) -> None:
    raw = _complete_raw_weakness()
    raw["ID"] = invalid_id

    with pytest.raises(
        ValueError,
        match="valid CWE identifier",
    ):
        CWEWeaknessMapper.map_weakness(
            raw
        )


@pytest.mark.parametrize(
    (
        "field_name",
        "value",
    ),
    [
        (
            "Name",
            "",
        ),
        (
            "Description",
            "   ",
        ),
        (
            "Name",
            123,
        ),
    ],
)
def test_required_text_is_validated(
    field_name: str,
    value: Any,
) -> None:
    raw = _complete_raw_weakness()
    raw[field_name] = value

    with pytest.raises(
        ValueError,
    ):
        CWEWeaknessMapper.map_weakness(
            raw
        )


def test_mapper_does_not_modify_input(
) -> None:
    raw = _complete_raw_weakness()
    original = deepcopy(raw)

    CWEWeaknessMapper.map_weakness(
        raw
    )

    assert raw == original


def test_invalid_nested_collection_is_rejected(
) -> None:
    raw = _complete_raw_weakness()

    raw["CommonConsequences"] = [
        "invalid",
    ]

    with pytest.raises(
        ValueError,
        match=(
            "CommonConsequences must "
            "contain mapping elements"
        ),
    ):
        CWEWeaknessMapper.map_weakness(
            raw
        )


def test_flat_platform_list_is_supported(
) -> None:
    raw = _complete_raw_weakness()

    raw["ApplicablePlatforms"] = [
        {
            "Type": "Language",
            "Class": (
                "Not Language-Specific"
            ),
            "Prevalence": "Undetermined",
        },
        {
            "Type": "Technology",
            "Name": "Web Server",
            "Prevalence": "Undetermined",
        },
    ]

    result = (
        CWEWeaknessMapper.map_weakness(
            raw
        )
    )

    assert result.applicable_platforms == (
        {
            "type": "Language",
            "Class": (
                "Not Language-Specific"
            ),
            "Prevalence": "Undetermined",
        },
        {
            "type": "Technology",
            "Name": "Web Server",
            "Prevalence": "Undetermined",
        },
    )

def test_scalar_capec_identifiers_are_supported(
) -> None:
    raw = _complete_raw_weakness()

    raw["RelatedAttackPatterns"] = [
        63,
        "CAPEC-100",
        "00063",
    ]

    result = (
        CWEWeaknessMapper.map_weakness(
            raw
        )
    )

    assert result.related_capec_ids == (
        "CAPEC-63",
        "CAPEC-100",
    )

def test_mixed_capec_shapes_are_supported(
) -> None:
    raw = _complete_raw_weakness()

    raw["RelatedAttackPatterns"] = [
        {
            "CAPECID": "63",
        },
        "CAPEC-100",
        {
            "ID": "CAPEC-66",
        },
        None,
        "invalid",
        {
            "Name": (
                "Missing CAPEC identifier"
            ),
        },
    ]

    result = (
        CWEWeaknessMapper.map_weakness(
            raw
        )
    )

    assert result.related_capec_ids == (
        "CAPEC-63",
        "CAPEC-100",
        "CAPEC-66",
    )
    
def test_invalid_capec_data_does_not_block_enrichment(
) -> None:
    raw = _complete_raw_weakness()

    raw["ID"] = "79"
    raw["Name"] = "Cross-site Scripting"
    raw["Description"] = (
        "Improper neutralization of web output."
    )

    raw["RelatedAttackPatterns"] = [
        None,
        True,
        "invalid",
        {
            "CAPECID": "invalid",
        },
        {
            "unexpected": "value",
        },
    ]

    result = (
        CWEWeaknessMapper.map_weakness(
            raw
        )
    )

    assert result.id == "CWE-79"

    assert result.name == (
        "Cross-site Scripting"
    )

    assert result.description == (
        "Improper neutralization "
        "of web output."
    )

    assert result.related_capec_ids == ()
    
    
def test_nested_capec_collection_is_supported(
) -> None:
    raw = _complete_raw_weakness()

    raw["RelatedAttackPatterns"] = {
        "RelatedAttackPattern": [
            {
                "CAPEC_ID": "63",
            },
            {
                "CAPECID": "100",
            },
        ],
    }

    result = (
        CWEWeaknessMapper.map_weakness(
            raw
        )
    )

    assert result.related_capec_ids == (
        "CAPEC-63",
        "CAPEC-100",
    )
    

def test_collection_size_is_bounded(
) -> None:
    raw = _complete_raw_weakness()

    raw["RelatedWeaknesses"] = [
        {
            "Nature": "ChildOf",
            "CweID": str(index + 1),
        }
        for index in range(
            CWEWeaknessMapper
            .MAX_COLLECTION_ITEMS
            + 1
        )
    ]

    with pytest.raises(
        ValueError,
        match=(
            "RelatedWeaknesses exceeds "
            "the maximum allowed size"
        ),
    ):
        CWEWeaknessMapper.map_weakness(
            raw
        )


@pytest.mark.parametrize(
    "invalid_payload",
    [
        None,
        [],
        "invalid",
    ],
)
def test_map_payload_rejects_non_mapping(
    invalid_payload: Any,
) -> None:
    with pytest.raises(
        TypeError,
        match="payload must be a mapping",
    ):
        CWEWeaknessMapper.map_payload(
            invalid_payload  # type: ignore[arg-type]
        )


@pytest.mark.parametrize(
    "invalid_weaknesses",
    [
        None,
        {},
        "invalid",
    ],
)
def test_map_payload_requires_weakness_list(
    invalid_weaknesses: Any,
) -> None:
    with pytest.raises(
        ValueError,
        match=(
            "payload must contain "
            "a Weaknesses list"
        ),
    ):
        CWEWeaknessMapper.map_payload(
            {
                "Weaknesses": (
                    invalid_weaknesses
                ),
            }
        )
        
def test_grouped_platform_mapping_supports_notes(
) -> None:
    raw = _complete_raw_weakness()

    raw["ApplicablePlatforms"] = {
        "Languages": [
            {
                "Name": "Python",
                "Prevalence": "Often",
            },
        ],
        "PlatformNotes": (
            "Applicable independently "
            "of the operating system."
        ),
    }

    result = (
        CWEWeaknessMapper.map_weakness(
            raw
        )
    )

    assert result.applicable_platforms == (
        {
            "type": "Languages",
            "Name": "Python",
            "Prevalence": "Often",
        },
        {
            "type": "PlatformNotes",
            "value": (
                "Applicable independently "
                "of the operating system."
            ),
        },
    )
    
def test_invalid_platform_list_element_is_rejected(
) -> None:
    raw = _complete_raw_weakness()

    raw["ApplicablePlatforms"] = [
        {
            "Type": "Language",
            "Name": "Python",
        },
        "invalid",
    ]

    with pytest.raises(
        ValueError,
        match=(
            "ApplicablePlatforms must "
            "contain mapping elements"
        ),
    ):
        CWEWeaknessMapper.map_weakness(
            raw
        )
        
def test_invalid_platform_root_type_is_rejected(
) -> None:
    raw = _complete_raw_weakness()

    raw["ApplicablePlatforms"] = (
        "invalid"
    )

    with pytest.raises(
        ValueError,
        match=(
            "ApplicablePlatforms must be "
            "a mapping or a list"
        ),
    ):
        CWEWeaknessMapper.map_weakness(
            raw
        )