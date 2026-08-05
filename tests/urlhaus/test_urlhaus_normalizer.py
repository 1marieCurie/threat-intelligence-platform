from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest

from application.ports.outbound.urlhaus_url_repository import (
    URLhausBlacklistData,
    URLhausURLData,
)
from application.services.urlhaus_normalizer import (
    URLhausNormalizationError,
    URLhausNormalizer,
)


def build_payload(
    **overrides: Any,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": 3_886_372,
        "urlhaus_reference": (
            "https://urlhaus.abuse.ch/"
            "url/3886372/"
        ),
        "url": (
            "http://59.180.140.134/"
            "malware"
        ),
        "url_status": "online",
        "host": "59.180.140.134",
        "date_added": (
            "2026-07-14 11:21:22 UTC"
        ),
        "threat": "malware_download",
        "blacklists": {
            "spamhaus_dbl": "not listed",
            "surbl": "listed",
        },
        "reporter": "example-reporter",
        "larted": "true",
        "tags": [
            "32-bit",
            "elf",
            "MIPS",
            "Mozi",
        ],
    }

    payload.update(
        overrides
    )

    return payload


def test_normalize_complete_record(
) -> None:
    raw_payload_id = uuid4()

    result = URLhausNormalizer().normalize(
        raw_payload_id=raw_payload_id,
        payload=build_payload(),
    )

    assert isinstance(
        result,
        URLhausURLData,
    )

    assert (
        result.raw_payload_id
        == raw_payload_id
    )

    assert result.urlhaus_id == 3_886_372

    assert result.malicious_url == (
        "http://59.180.140.134/malware"
    )

    assert (
        result.hostname
        == "59.180.140.134"
    )

    assert result.url_status == "online"

    assert result.date_added == datetime(
        2026,
        7,
        14,
        11,
        21,
        22,
        tzinfo=UTC,
    )

    assert (
        result.threat_type
        == "malware_download"
    )

    assert (
        result.reporter
        == "example-reporter"
    )

    assert result.larted is True

    assert result.tags == (
        "32-bit",
        "elf",
        "mips",
        "mozi",
    )

    assert result.blacklists == (
        URLhausBlacklistData(
            name="spamhaus_dbl",
            status="not listed",
        ),
        URLhausBlacklistData(
            name="surbl",
            status="listed",
        ),
    )

    assert (
        result.normalizer_version
        == "1.0.0"
    )


def test_normalize_accepts_numeric_string_id(
) -> None:
    result = URLhausNormalizer().normalize(
        raw_payload_id=uuid4(),
        payload=build_payload(
            id=" 003886372 "
        ),
    )

    assert (
        result.urlhaus_id
        == 3_886_372
    )


@pytest.mark.parametrize(
    "invalid_identifier",
    [
        None,
        True,
        False,
        0,
        -1,
        "",
        "invalid",
        1.5,
    ],
)
def test_normalize_rejects_invalid_identifier(
    invalid_identifier: Any,
) -> None:
    with pytest.raises(
        URLhausNormalizationError,
        match="id must be a positive integer",
    ):
        URLhausNormalizer().normalize(
            raw_payload_id=uuid4(),
            payload=build_payload(
                id=invalid_identifier
            ),
        )


@pytest.mark.parametrize(
    "invalid_url",
    [
        "",
        "javascript:alert(1)",
        "ftp://example.test/file",
        "http:///missing-host",
        "http://example.test/invalid path",
    ],
)
def test_normalize_rejects_invalid_url(
    invalid_url: str,
) -> None:
    with pytest.raises(
        URLhausNormalizationError,
    ):
        URLhausNormalizer().normalize(
            raw_payload_id=uuid4(),
            payload=build_payload(
                url=invalid_url
            ),
        )


def test_normalize_rejects_url_over_limit(
) -> None:
    oversized_url = (
        "https://example.test/"
        + "a" * 4_100
    )

    with pytest.raises(
        URLhausNormalizationError,
        match="exceeds 4096 characters",
    ):
        URLhausNormalizer().normalize(
            raw_payload_id=uuid4(),
            payload=build_payload(
                url=oversized_url,
                host="example.test",
            ),
        )


def test_normalize_rejects_host_mismatch(
) -> None:
    with pytest.raises(
        URLhausNormalizationError,
        match=(
            "host must match "
            "the URL hostname"
        ),
    ):
        URLhausNormalizer().normalize(
            raw_payload_id=uuid4(),
            payload=build_payload(
                host="different.example"
            ),
        )


def test_normalize_derives_hostname_when_host_missing(
) -> None:
    result = URLhausNormalizer().normalize(
        raw_payload_id=uuid4(),
        payload=build_payload(
            host=None,
            url=(
                "https://Malicious.Example/"
                "payload"
            ),
        ),
    )

    assert (
        result.hostname
        == "malicious.example"
    )


def test_normalize_converts_iso_datetime_to_utc(
) -> None:
    result = URLhausNormalizer().normalize(
        raw_payload_id=uuid4(),
        payload=build_payload(
            date_added=(
                "2026-07-14T13:21:22+02:00"
            )
        ),
    )

    assert result.date_added == datetime(
        2026,
        7,
        14,
        11,
        21,
        22,
        tzinfo=UTC,
    )


def test_normalize_rejects_naive_datetime(
) -> None:
    with pytest.raises(
        URLhausNormalizationError,
        match="must include a timezone",
    ):
        URLhausNormalizer().normalize(
            raw_payload_id=uuid4(),
            payload=build_payload(
                date_added=(
                    "2026-07-14T11:21:22"
                )
            ),
        )


@pytest.mark.parametrize(
    (
        "raw_value",
        "expected_value",
    ),
    [
        ("true", True),
        ("YES", True),
        ("1", True),
        ("false", False),
        ("No", False),
        ("0", False),
        ("", None),
        (None, None),
    ],
)
def test_normalize_larted_boolean(
    raw_value: Any,
    expected_value: bool | None,
) -> None:
    result = URLhausNormalizer().normalize(
        raw_payload_id=uuid4(),
        payload=build_payload(
            larted=raw_value
        ),
    )

    assert (
        result.larted
        is expected_value
    )


def test_normalize_deduplicates_tags(
) -> None:
    result = URLhausNormalizer().normalize(
        raw_payload_id=uuid4(),
        payload=build_payload(
            tags=[
                "ELF",
                "elf",
                "",
                None,
                "Mozi",
                "mozi",
            ]
        ),
    )

    assert result.tags == (
        "elf",
        "mozi",
    )


def test_normalize_bounds_tags_before_processing(
) -> None:
    result = URLhausNormalizer().normalize(
        raw_payload_id=uuid4(),
        payload=build_payload(
            tags=[
                f"tag-{index}"
                for index in range(150)
            ]
        ),
    )

    assert len(
        result.tags
    ) == 100

    assert result.tags[0] == "tag-0"
    assert result.tags[-1] == "tag-99"


def test_normalize_bounds_blacklists(
) -> None:
    result = URLhausNormalizer().normalize(
        raw_payload_id=uuid4(),
        payload=build_payload(
            blacklists={
                f"provider-{index}": "listed"
                for index in range(75)
            }
        ),
    )

    assert len(
        result.blacklists
    ) == 50


def test_normalize_ignores_invalid_auxiliary_items(
) -> None:
    result = URLhausNormalizer().normalize(
        raw_payload_id=uuid4(),
        payload=build_payload(
            tags=[
                "elf",
                None,
                123,
                "",
            ],
            blacklists={
                "provider": "listed",
                "": "ignored",
                "invalid-status": None,
            },
        ),
    )

    assert result.tags == (
        "elf",
    )

    assert result.blacklists == (
        URLhausBlacklistData(
            name="provider",
            status="listed",
        ),
    )


def test_normalize_ignores_detail_enrichment_fields(
) -> None:
    result = URLhausNormalizer().normalize(
        raw_payload_id=uuid4(),
        payload=build_payload(
            payloads=[
                {
                    "response_sha256": (
                        "a" * 64
                    ),
                }
            ],
            last_online=(
                "2026-07-15 10:00:00 UTC"
            ),
        ),
    )

    assert isinstance(
        result,
        URLhausURLData,
    )

    assert not hasattr(
        result,
        "payloads",
    )


def test_normalize_does_not_mutate_payload(
) -> None:
    payload = build_payload()
    original_payload = deepcopy(
        payload
    )

    URLhausNormalizer().normalize(
        raw_payload_id=uuid4(),
        payload=payload,
    )

    assert payload == original_payload


def test_normalization_error_does_not_expose_ioc(
) -> None:
    sensitive_value = (
        "javascript:"
        "private-token@malicious.example"
    )

    with pytest.raises(
        URLhausNormalizationError,
    ) as captured_error:
        URLhausNormalizer().normalize(
            raw_payload_id=uuid4(),
            payload=build_payload(
                url=sensitive_value
            ),
        )

    error_message = str(
        captured_error.value
    )

    assert (
        sensitive_value
        not in error_message
    )

    assert (
        "private-token"
        not in error_message
    )


def test_normalize_rejects_invalid_raw_payload_id(
) -> None:
    with pytest.raises(
        TypeError,
        match=(
            "raw_payload_id must be a UUID"
        ),
    ):
        URLhausNormalizer().normalize(
            raw_payload_id="invalid",  # type: ignore[arg-type]
            payload=build_payload(),
        )


def test_normalize_rejects_non_mapping_payload(
) -> None:
    with pytest.raises(
        TypeError,
        match="payload must be a mapping",
    ):
        URLhausNormalizer().normalize(
            raw_payload_id=uuid4(),
            payload=[],  # type: ignore[arg-type]
        )
        
def test_normalize_converts_null_tags_to_empty_collection(
) -> None:
    result = URLhausNormalizer().normalize(
        raw_payload_id=uuid4(),
        payload=build_payload(
            tags=None
        ),
    )

    assert result.tags == ()