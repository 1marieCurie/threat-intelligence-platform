from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from application.services.phishtank_normalizer import (
    PhishTankNormalizationError,
    PhishTankNormalizer,
)


@pytest.fixture
def raw_payload_id() -> UUID:
    return uuid4()


@pytest.fixture
def complete_record() -> dict[str, object]:
    return {
        "phish_id": "9477391",
        "url": (
            "https://User:Secret@"
            "Fake-Login.Example.Invalid/"
            "account/verify"
        ),
        "phish_detail_url": (
            "https://www.phishtank.com/"
            "phish_detail.php?"
            "phish_id=9477391"
        ),
        "submission_time": (
            "2026-07-13T11:03:01Z"
        ),
        "verified": " yes ",
        "verification_time": (
            "2026-07-13T11:52:26+00:00"
        ),
        "online": True,
        "details": [
            {
                "ip_address": "192.0.2.10",
                "cidr_block": "192.0.2.10/24",
                "announcing_network": " 64500 ",
                "rir": " ARIN ",
                "country": " ma ",
                "detail_time": (
                    "2026-07-13T11:12:10Z"
                ),
            },
            {
                "ip_address": "192.0.2.10",
                "cidr_block": "192.0.2.10/24",
                "announcing_network": " 64500 ",
                "rir": " ARIN ",
                "country": " ma ",
                "detail_time": (
                    "2026-07-13T11:12:10Z"
                ),
            },
        ],
        "target": " Other ",
    }


def test_normalize_maps_complete_record(
    raw_payload_id: UUID,
    complete_record: dict[str, object],
) -> None:
    result = (
        PhishTankNormalizer()
        .normalize(
            raw_payload_id=raw_payload_id,
            payload=complete_record,
        )
    )

    assert (
        result.raw_payload_id
        == raw_payload_id
    )

    assert result.phish_id == 9477391

    assert result.phishing_url == (
        "https://User:Secret@"
        "Fake-Login.Example.Invalid/"
        "account/verify"
    )

    assert result.hostname == (
        "fake-login.example.invalid"
    )

    assert result.phish_detail_url == (
        "https://www.phishtank.com/"
        "phish_detail.php?"
        "phish_id=9477391"
    )

    assert result.submission_time == datetime(
        2026,
        7,
        13,
        11,
        3,
        1,
        tzinfo=UTC,
    )

    assert result.verification_time == datetime(
        2026,
        7,
        13,
        11,
        52,
        26,
        tzinfo=UTC,
    )

    assert result.verified is True
    assert result.online is True
    assert result.target == "Other"

    assert len(
        result.network_details
    ) == 1

    detail = result.network_details[0]

    assert detail.ip_address == (
        "192.0.2.10"
    )

    assert detail.cidr_block == (
        "192.0.2.0/24"
    )

    assert (
        detail.announcing_network
        == "64500"
    )

    assert detail.rir == "arin"
    assert detail.country == "MA"

    assert detail.detail_time == datetime(
        2026,
        7,
        13,
        11,
        12,
        10,
        tzinfo=UTC,
    )

    assert (
        result.normalizer_version
        == "1.0.1"
    )


@pytest.mark.parametrize(
    (
        "source_value",
        "expected",
    ),
    [
        ("yes", True),
        ("Y", True),
        ("true", True),
        ("1", True),
        ("no", False),
        ("N", False),
        ("false", False),
        ("0", False),
        (True, True),
        (False, False),
        ("", None),
        (None, None),
    ],
)
def test_boolean_representations_are_normalized(
    raw_payload_id: UUID,
    source_value: object,
    expected: bool | None,
) -> None:
    result = (
        PhishTankNormalizer()
        .normalize(
            raw_payload_id=raw_payload_id,
            payload={
                "phish_id": 1,
                "url": (
                    "https://example.invalid/login"
                ),
                "verified": source_value,
            },
        )
    )

    assert result.verified is expected


@pytest.mark.parametrize(
    "invalid_phish_id",
    [
        None,
        True,
        0,
        -1,
        "",
        "abc",
        "1.5",
        1.5,
    ],
)
def test_invalid_phish_id_is_rejected(
    raw_payload_id: UUID,
    invalid_phish_id: object,
) -> None:
    with pytest.raises(
        PhishTankNormalizationError,
        match="phish_id",
    ):
        PhishTankNormalizer().normalize(
            raw_payload_id=raw_payload_id,
            payload={
                "phish_id": invalid_phish_id,
                "url": (
                    "https://example.invalid/login"
                ),
            },
        )


@pytest.mark.parametrize(
    "invalid_url",
    [
        None,
        "",
        "example.invalid/login",
        "ftp://example.invalid/file",
        "https:///missing-host",
        (
            "https://example.invalid:"
            "invalid/login"
        ),
        (
            "https://example.invalid/"
            "path with space"
        ),
    ],
)
def test_invalid_phishing_url_is_rejected(
    raw_payload_id: UUID,
    invalid_url: object,
) -> None:
    with pytest.raises(
        PhishTankNormalizationError,
        match="url",
    ):
        PhishTankNormalizer().normalize(
            raw_payload_id=raw_payload_id,
            payload={
                "phish_id": 1,
                "url": invalid_url,
            },
        )


def test_url_error_does_not_expose_credentials(
    raw_payload_id: UUID,
) -> None:
    sensitive_url = (
        "ftp://user:super-secret@"
        "example.invalid/file"
    )

    with pytest.raises(
        PhishTankNormalizationError,
    ) as captured_error:
        PhishTankNormalizer().normalize(
            raw_payload_id=raw_payload_id,
            payload={
                "phish_id": 1,
                "url": sensitive_url,
            },
        )

    assert (
        sensitive_url
        not in str(
            captured_error.value
        )
    )

    assert (
        "super-secret"
        not in str(
            captured_error.value
        )
    )


def test_ipv6_hostname_is_extracted(
    raw_payload_id: UUID,
) -> None:
    result = (
        PhishTankNormalizer()
        .normalize(
            raw_payload_id=raw_payload_id,
            payload={
                "phish_id": 2,
                "url": (
                    "http://[2001:db8::10]/login"
                ),
            },
        )
    )

    assert result.hostname == (
        "2001:db8::10"
    )


def test_optional_fields_can_be_missing(
    raw_payload_id: UUID,
) -> None:
    result = (
        PhishTankNormalizer()
        .normalize(
            raw_payload_id=raw_payload_id,
            payload={
                "phish_id": 3,
                "url": (
                    "https://example.invalid/login"
                ),
            },
        )
    )

    assert result.phish_detail_url is None
    assert result.submission_time is None
    assert result.verification_time is None
    assert result.verified is None
    assert result.online is None
    assert result.target is None
    assert result.network_details == ()


def test_invalid_boolean_is_rejected(
    raw_payload_id: UUID,
) -> None:
    with pytest.raises(
        PhishTankNormalizationError,
        match="verified",
    ):
        PhishTankNormalizer().normalize(
            raw_payload_id=raw_payload_id,
            payload={
                "phish_id": 4,
                "url": (
                    "https://example.invalid/login"
                ),
                "verified": "unknown",
            },
        )


def test_naive_timestamp_is_rejected(
    raw_payload_id: UUID,
) -> None:
    with pytest.raises(
        PhishTankNormalizationError,
        match="timezone",
    ):
        PhishTankNormalizer().normalize(
            raw_payload_id=raw_payload_id,
            payload={
                "phish_id": 5,
                "url": (
                    "https://example.invalid/login"
                ),
                "submission_time": (
                    "2026-07-13T11:03:01"
                ),
            },
        )


def test_verification_before_submission_is_rejected(
    raw_payload_id: UUID,
) -> None:
    with pytest.raises(
        PhishTankNormalizationError,
        match="verification_time",
    ):
        PhishTankNormalizer().normalize(
            raw_payload_id=raw_payload_id,
            payload={
                "phish_id": 6,
                "url": (
                    "https://example.invalid/login"
                ),
                "submission_time": (
                    "2026-07-13T12:00:00Z"
                ),
                "verification_time": (
                    "2026-07-13T11:00:00Z"
                ),
            },
        )


def test_invalid_network_values_are_ignored(
    raw_payload_id: UUID,
) -> None:
    result = (
        PhishTankNormalizer()
        .normalize(
            raw_payload_id=raw_payload_id,
            payload={
                "phish_id": 7,
                "url": (
                    "https://example.invalid/login"
                ),
                "details": [
                    {
                        "ip_address": (
                            "not-an-ip"
                        ),
                        "cidr_block": (
                            "not-a-cidr"
                        ),
                        "country": "invalid",
                    },
                    "invalid-detail",
                ],
            },
        )
    )

    assert result.network_details == ()


def test_network_details_are_bounded(
    raw_payload_id: UUID,
) -> None:
    maximum_details = 100

    payload: dict[str, object] = {
        "phish_id": "9477391",
        "url": (
            "https://example.invalid/"
            "login"
        ),
        "details": [
            {
                "ip_address": (
                    f"192.0.2.{index}"
                ),
            }
            for index in range(
                1,
                maximum_details + 1,
            )
        ],
    }

    details = payload["details"]

    assert isinstance(
        details,
        list,
    )

    details.append(
        {
            "ip_address": (
                "198.51.100.10"
            ),
        }
    )

    result = (
        PhishTankNormalizer()
        .normalize(
            raw_payload_id=raw_payload_id,
            payload=payload,
        )
    )

    assert len(
        result.network_details
    ) == maximum_details

    assert all(
        detail.ip_address
        != "198.51.100.10"
        for detail
        in result.network_details
    )

def test_invalid_details_type_is_rejected(
    raw_payload_id: UUID,
) -> None:
    with pytest.raises(
        PhishTankNormalizationError,
        match="details",
    ):
        PhishTankNormalizer().normalize(
            raw_payload_id=raw_payload_id,
            payload={
                "phish_id": 9,
                "url": (
                    "https://example.invalid/login"
                ),
                "details": (
                    "invalid"
                ),
            },
        )


def test_input_payload_is_not_modified(
    raw_payload_id: UUID,
    complete_record: dict[str, object],
) -> None:
    original = deepcopy(
        complete_record
    )

    PhishTankNormalizer().normalize(
        raw_payload_id=raw_payload_id,
        payload=complete_record,
    )

    assert complete_record == original


def test_invalid_raw_payload_id_is_rejected(
) -> None:
    with pytest.raises(
        TypeError,
        match="raw_payload_id",
    ):
        PhishTankNormalizer().normalize(
            raw_payload_id=(
                "invalid"  # type: ignore[arg-type]
            ),
            payload={
                "phish_id": 10,
                "url": (
                    "https://example.invalid/login"
                ),
            },
        )


def test_non_mapping_payload_is_rejected(
    raw_payload_id: UUID,
) -> None:
    with pytest.raises(
        TypeError,
        match="payload",
    ):
        PhishTankNormalizer().normalize(
            raw_payload_id=raw_payload_id,
            payload=[],  # type: ignore[arg-type]
        )