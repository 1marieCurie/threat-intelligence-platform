from __future__ import annotations

import pytest

from domain.threat_category import ThreatCategory


def test_unit_category_values_are_stable() -> None:
    assert (
        ThreatCategory.VULNERABILITY.value
        == "vulnerability"
    )

    assert (
        ThreatCategory.PHISHING.value
        == "phishing"
    )

    assert (
        ThreatCategory.MALWARE_DISTRIBUTION.value
        == "malware_distribution"
    )

    assert (
        ThreatCategory.MALWARE.value
        == "malware"
    )

    assert (
        ThreatCategory.CAMPAIGN.value
        == "campaign"
    )

    assert (
        ThreatCategory.INFRASTRUCTURE.value
        == "infrastructure"
    )

    assert (
        ThreatCategory.UNKNOWN.value
        == "unknown"
    )


def test_unit_category_is_string_compatible() -> None:
    category = ThreatCategory.VULNERABILITY

    assert isinstance(
        category,
        str,
    )

    assert category == "vulnerability"


@pytest.mark.parametrize(
    (
        "raw_value",
        "expected",
    ),
    [
        (
            "vulnerability",
            ThreatCategory.VULNERABILITY,
        ),
        (
            "phishing",
            ThreatCategory.PHISHING,
        ),
        (
            "malware_distribution",
            ThreatCategory.MALWARE_DISTRIBUTION,
        ),
        (
            "malware",
            ThreatCategory.MALWARE,
        ),
        (
            "campaign",
            ThreatCategory.CAMPAIGN,
        ),
        (
            "infrastructure",
            ThreatCategory.INFRASTRUCTURE,
        ),
        (
            "unknown",
            ThreatCategory.UNKNOWN,
        ),
    ],
)
def test_unit_category_can_be_created_from_value(
    raw_value: str,
    expected: ThreatCategory,
) -> None:
    assert (
        ThreatCategory(raw_value)
        is expected
    )


def test_unit_invalid_category_value_is_rejected() -> None:
    with pytest.raises(
        ValueError,
    ):
        ThreatCategory(
            "invalid-category"
        )