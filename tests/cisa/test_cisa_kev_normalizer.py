from __future__ import annotations

from copy import deepcopy
from datetime import date
from uuid import uuid4

import pytest

from application.services.cisa_kev_normalizer import (
    CisaKevNormalizationError,
    CisaKevNormalizer,
)


def _valid_payload() -> dict[str, object]:
    return {
        "cveID": "CVE-2026-12345",
        "vendorProject": "Test Vendor",
        "product": "Test Product",
        "vulnerabilityName": (
            "Test Product vulnerability"
        ),
        "dateAdded": "2026-07-20",
        "shortDescription": (
            "A vulnerability affects the product."
        ),
        "requiredAction": (
            "Apply mitigations provided by the vendor."
        ),
        "dueDate": "2026-08-10",
        "knownRansomwareCampaignUse": "Unknown",
        "notes": "Additional information.",
        "cwes": [
            "CWE-79",
            "CWE-89",
        ],
    }


def test_normalize_maps_valid_payload() -> None:
    raw_payload_id = uuid4()

    result = CisaKevNormalizer().normalize(
        raw_payload_id=raw_payload_id,
        payload=_valid_payload(),
    )

    assert result.raw_payload_id == raw_payload_id
    assert result.cve_id == "CVE-2026-12345"
    assert result.vendor_project == "Test Vendor"
    assert result.product == "Test Product"
    assert result.date_added == date(
        2026,
        7,
        20,
    )
    assert result.due_date == date(
        2026,
        8,
        10,
    )
    assert (
        result.known_ransomware_campaign_use
        == "unknown"
    )
    assert result.cwes == (
        "CWE-79",
        "CWE-89",
    )
    assert result.normalizer_version == "1.0.0"


def test_normalize_trims_and_deduplicates_values() -> None:
    payload = _valid_payload()

    payload["cveID"] = " cve-2026-12345 "
    payload["vendorProject"] = " Test Vendor "
    payload["knownRansomwareCampaignUse"] = (
        " Known "
    )
    payload["cwes"] = [
        " cwe-79 ",
        "CWE-79",
        "cwe-89",
    ]

    result = CisaKevNormalizer().normalize(
        raw_payload_id=uuid4(),
        payload=payload,
    )

    assert result.cve_id == "CVE-2026-12345"
    assert result.vendor_project == "Test Vendor"
    assert (
        result.known_ransomware_campaign_use
        == "known"
    )
    assert result.cwes == (
        "CWE-79",
        "CWE-89",
    )


def test_empty_notes_become_none() -> None:
    payload = _valid_payload()
    payload["notes"] = "   "

    result = CisaKevNormalizer().normalize(
        raw_payload_id=uuid4(),
        payload=payload,
    )

    assert result.notes is None


def test_missing_cwes_becomes_empty_tuple() -> None:
    payload = _valid_payload()
    payload.pop("cwes")

    result = CisaKevNormalizer().normalize(
        raw_payload_id=uuid4(),
        payload=payload,
    )

    assert result.cwes == ()


@pytest.mark.parametrize(
    "field_name",
    [
        "cveID",
        "vendorProject",
        "product",
        "vulnerabilityName",
        "dateAdded",
        "shortDescription",
        "requiredAction",
        "dueDate",
        "knownRansomwareCampaignUse",
    ],
)
def test_missing_required_field_is_rejected(
    field_name: str,
) -> None:
    payload = _valid_payload()
    payload.pop(field_name)

    with pytest.raises(
        CisaKevNormalizationError,
    ):
        CisaKevNormalizer().normalize(
            raw_payload_id=uuid4(),
            payload=payload,
        )


@pytest.mark.parametrize(
    "cve_id",
    [
        "",
        "GHSA-aaaa-bbbb-cccc",
        "CVE-26-1234",
        "CVE-2026-12",
        "CVE-2026-ABC",
    ],
)
def test_invalid_cve_is_rejected(
    cve_id: str,
) -> None:
    payload = _valid_payload()
    payload["cveID"] = cve_id

    with pytest.raises(
        CisaKevNormalizationError,
        match="cveID",
    ):
        CisaKevNormalizer().normalize(
            raw_payload_id=uuid4(),
            payload=payload,
        )


@pytest.mark.parametrize(
    "field_name",
    [
        "dateAdded",
        "dueDate",
    ],
)
@pytest.mark.parametrize(
    "invalid_date",
    [
        "",
        "2026/07/20",
        "20-07-2026",
        "2026-02-30",
        "2026-7-20",
    ],
)
def test_invalid_date_is_rejected(
    field_name: str,
    invalid_date: str,
) -> None:
    payload = _valid_payload()
    payload[field_name] = invalid_date

    with pytest.raises(
        CisaKevNormalizationError,
        match=field_name,
    ):
        CisaKevNormalizer().normalize(
            raw_payload_id=uuid4(),
            payload=payload,
        )


def test_due_date_before_date_added_is_rejected() -> None:
    payload = _valid_payload()
    payload["dateAdded"] = "2026-08-10"
    payload["dueDate"] = "2026-08-09"

    with pytest.raises(
        CisaKevNormalizationError,
        match="dueDate",
    ):
        CisaKevNormalizer().normalize(
            raw_payload_id=uuid4(),
            payload=payload,
        )


@pytest.mark.parametrize(
    "value",
    [
        "",
        "yes",
        "confirmed",
        None,
        True,
    ],
)
def test_invalid_ransomware_value_is_rejected(
    value: object,
) -> None:
    payload = _valid_payload()
    payload["knownRansomwareCampaignUse"] = value

    with pytest.raises(
        CisaKevNormalizationError,
        match="knownRansomwareCampaignUse",
    ):
        CisaKevNormalizer().normalize(
            raw_payload_id=uuid4(),
            payload=payload,
        )


@pytest.mark.parametrize(
    "cwes",
    [
        "CWE-79",
        ["CWE-79", 89],
        ["INVALID"],
        [""],
    ],
)
def test_invalid_cwes_are_rejected(
    cwes: object,
) -> None:
    payload = _valid_payload()
    payload["cwes"] = cwes

    with pytest.raises(
        CisaKevNormalizationError,
    ):
        CisaKevNormalizer().normalize(
            raw_payload_id=uuid4(),
            payload=payload,
        )


def test_input_payload_is_not_modified() -> None:
    payload = _valid_payload()
    original_payload = deepcopy(payload)

    CisaKevNormalizer().normalize(
        raw_payload_id=uuid4(),
        payload=payload,
    )

    assert payload == original_payload


def test_invalid_raw_payload_id_is_rejected() -> None:
    with pytest.raises(
        TypeError,
        match="raw_payload_id",
    ):
        CisaKevNormalizer().normalize(
            raw_payload_id="invalid",  # type: ignore[arg-type]
            payload=_valid_payload(),
        )


def test_non_mapping_payload_is_rejected() -> None:
    with pytest.raises(
        TypeError,
        match="payload",
    ):
        CisaKevNormalizer().normalize(
            raw_payload_id=uuid4(),
            payload=[],  # type: ignore[arg-type]
        )