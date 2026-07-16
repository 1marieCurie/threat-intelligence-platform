from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest

from application.services.phishtank_threat_source import (
    PhishTankThreatSource,
)
from domain.collection_result import CollectionResult
from domain.indicator import Indicator
from domain.threat import Threat
from domain.threat_category import ThreatCategory


# ============================================================
# Fake connector
# ============================================================


class FakePhishTankConnector:
    """
    Fake connector used to test PhishTankThreatSource without
    performing network or filesystem operations.
    """

    def __init__(
        self,
        *,
        records: Optional[List[Dict[str, Any]]] = None,
        state: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.records = records or []
        self.state = state or {}

        self.fetch_calls: List[Dict[str, Any]] = []
        self.state_calls = 0

    def fetch_raw(
        self,
        *,
        force_download: bool = False,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        self.fetch_calls.append(
            {
                "force_download": force_download,
                "limit": limit,
            }
        )

        if limit is None:
            return list(self.records)

        return list(self.records[:limit])

    def get_local_state(self) -> Dict[str, Any]:
        self.state_calls += 1
        return dict(self.state)


# ============================================================
# Fixtures and helpers
# ============================================================


@pytest.fixture
def complete_raw_record() -> Dict[str, Any]:
    return {
        "phish_id": 9477391,
        "url": (
            "https://fake-login.example.invalid/"
            "account/verify"
        ),
        "phish_detail_url": (
            "https://www.phishtank.com/"
            "phish_detail.php?phish_id=9477391"
        ),
        "submission_time": (
            "2026-07-13T11:03:01+00:00"
        ),
        "verified": "yes",
        "verification_time": (
            "2026-07-13T11:52:26+00:00"
        ),
        "online": "yes",
        "details": [
            {
                "ip_address": "192.0.2.10",
                "cidr_block": "192.0.2.0/24",
                "announcing_network": "64500",
                "rir": "arin",
                "country": "MA",
                "detail_time": (
                    "2026-07-13T11:12:10+00:00"
                ),
            }
        ],
        "target": "Other",
    }


@pytest.fixture
def sync_state() -> Dict[str, Any]:
    return {
        "source": "PHISHTANK",
        "etag": '"etag-123"',
        "last_modified": (
            "Mon, 13 Jul 2026 12:23:00 GMT"
        ),
        "content_length": 2840000,
        "downloaded_at": (
            "2026-07-13T13:45:47+00:00"
        ),
        "dump_path": (
            "data/phishtank/online-valid.json.bz2"
        ),
        "downloaded": True,
        "used_local_snapshot": False,
    }


def create_source(
    *,
    records: Optional[List[Dict[str, Any]]] = None,
    state: Optional[Dict[str, Any]] = None,
    limit: Optional[int] = None,
    force_download: bool = False,
) -> tuple[
    PhishTankThreatSource,
    FakePhishTankConnector,
]:
    connector = FakePhishTankConnector(
        records=records,
        state=state,
    )

    source = PhishTankThreatSource(
        connector=connector,  # type: ignore[arg-type]
        limit=limit,
        force_download=force_download,
    )

    return source, connector


def find_indicator(
    threat: Threat,
    *,
    indicator_type: str,
    value: Optional[str] = None,
) -> Indicator:
    for indicator in threat.indicators:
        if indicator.type != indicator_type:
            continue

        if value is not None and indicator.value != value:
            continue

        return indicator

    raise AssertionError(
        f"Indicator not found: type={indicator_type}, "
        f"value={value}"
    )


# ============================================================
# Initialization and source contract
# ============================================================


def test_source_name() -> None:
    source, _ = create_source()

    assert source.name() == "PHISHTANK"


def test_source_constants() -> None:
    assert PhishTankThreatSource.SOURCE_NAME == "PHISHTANK"
    assert (
        PhishTankThreatSource.THREAT_CATEGORY
        is ThreatCategory.PHISHING
    )


@pytest.mark.parametrize(
    "invalid_limit",
    [
        -1,
        -10,
    ],
)
def test_source_rejects_negative_limit(
    invalid_limit: int,
) -> None:
    connector = FakePhishTankConnector()

    with pytest.raises(
        ValueError,
        match="limit must be greater than or equal to zero",
    ):
        PhishTankThreatSource(
            connector=connector,  # type: ignore[arg-type]
            limit=invalid_limit,
        )


def test_source_accepts_zero_limit() -> None:
    source, _ = create_source(
        limit=0
    )

    assert source.limit == 0


def test_fetch_raw_calls_connector_with_configuration(
    complete_raw_record: Dict[str, Any],
) -> None:
    source, connector = create_source(
        records=[complete_raw_record],
        limit=5,
        force_download=True,
    )

    records = source.fetch_raw()

    assert records == [complete_raw_record]

    assert connector.fetch_calls == [
        {
            "force_download": True,
            "limit": 5,
        }
    ]


# ============================================================
# Main record mapping
# ============================================================


def test_maps_complete_record_to_threat(
    complete_raw_record: Dict[str, Any],
) -> None:
    source, _ = create_source()

    threats = source.parse(
        [complete_raw_record]
    )

    assert len(threats) == 1

    threat = threats[0]

    assert isinstance(threat, Threat)
    assert threat.id == "PHISHTANK-9477391"

    assert threat.external_ids == {
        "PHISHTANK": ["9477391"],
    }

    assert threat.source == "PHISHTANK"
    assert threat.category is ThreatCategory.PHISHING

    assert threat.title == (
        "Verified online phishing URL targeting "
        "unknown target"
    )

    assert threat.description == (
        "A verified phishing URL targeting Other was "
        "reported by PhishTank and is currently online."
    )

    assert threat.published_date == (
        "2026-07-13T11:03:01+00:00"
    )

    assert threat.reviewed_date == (
        "2026-07-13T11:52:26+00:00"
    )

    assert threat.source_dates == {
        "submission_time": (
            "2026-07-13T11:03:01+00:00"
        ),
        "verification_time": (
            "2026-07-13T11:52:26+00:00"
        ),
    }

    assert threat.raw == complete_raw_record
    assert threat.raw is not complete_raw_record


def test_maps_phishtank_reference_and_source_url(
    complete_raw_record: Dict[str, Any],
) -> None:
    source, _ = create_source()

    threat = source.parse(
        [complete_raw_record]
    )[0]

    expected_url = (
        "https://www.phishtank.com/"
        "phish_detail.php?phish_id=9477391"
    )

    assert threat.references == [expected_url]

    assert threat.source_urls == {
        "PHISHTANK": expected_url,
    }


def test_maps_expected_labels(
    complete_raw_record: Dict[str, Any],
) -> None:
    source, _ = create_source()

    threat = source.parse(
        [complete_raw_record]
    )[0]

    assert threat.labels == [
        "phishing",
        "malicious-url",
        "verified",
        "online",
        "target:other",
    ]


def test_maps_known_target_in_title() -> None:
    raw_record = {
        "phish_id": 100,
        "url": "https://allegro.example.invalid/login",
        "verified": "yes",
        "online": "yes",
        "target": "Allegro",
        "details": [],
    }

    source, _ = create_source()

    threat = source.parse(
        [raw_record]
    )[0]

    assert threat.title == (
        "Verified online phishing URL targeting Allegro"
    )

    assert "target:allegro" in threat.labels


# ============================================================
# URL and hostname indicators
# ============================================================


def test_creates_url_indicator(
    complete_raw_record: Dict[str, Any],
) -> None:
    source, _ = create_source()

    threat = source.parse(
        [complete_raw_record]
    )[0]

    indicator = find_indicator(
        threat,
        indicator_type="url",
    )

    assert indicator.value == (
        "https://fake-login.example.invalid/"
        "account/verify"
    )

    assert indicator.confidence == 1.0

    assert indicator.metadata == {
        "source": "PHISHTANK",
        "verified": True,
        "online": True,
    }


def test_derives_domain_indicator_from_url(
    complete_raw_record: Dict[str, Any],
) -> None:
    source, _ = create_source()

    threat = source.parse(
        [complete_raw_record]
    )[0]

    indicator = find_indicator(
        threat,
        indicator_type="domain",
        value="fake-login.example.invalid",
    )

    assert indicator.confidence == 1.0

    assert indicator.metadata == {
        "source": "PHISHTANK",
        "verified": True,
        "online": True,
        "derived_from": "url",
    }


def test_url_with_ipv4_hostname_creates_ipv4_indicator() -> None:
    raw_record = {
        "phish_id": 101,
        "url": "http://192.0.2.55/login",
        "verified": "yes",
        "online": "yes",
        "details": [],
    }

    source, _ = create_source()

    threat = source.parse(
        [raw_record]
    )[0]

    indicator = find_indicator(
        threat,
        indicator_type="ipv4",
        value="192.0.2.55",
    )

    assert indicator.metadata["derived_from"] == "url"


def test_url_with_ipv6_hostname_creates_ipv6_indicator() -> None:
    raw_record = {
        "phish_id": 102,
        "url": "http://[2001:db8::10]/login",
        "verified": "yes",
        "online": "yes",
        "details": [],
    }

    source, _ = create_source()

    threat = source.parse(
        [raw_record]
    )[0]

    indicator = find_indicator(
        threat,
        indicator_type="ipv6",
        value="2001:db8::10",
    )

    assert indicator.metadata["derived_from"] == "url"


# ============================================================
# Network indicators
# ============================================================


def test_creates_ipv4_indicator_from_details(
    complete_raw_record: Dict[str, Any],
) -> None:
    source, _ = create_source()

    threat = source.parse(
        [complete_raw_record]
    )[0]

    indicator = find_indicator(
        threat,
        indicator_type="ipv4",
        value="192.0.2.10",
    )

    assert indicator.confidence == 1.0

    assert indicator.metadata == {
        "source": "PHISHTANK",
        "verified": True,
        "online": True,
        "cidr_block": "192.0.2.0/24",
        "announcing_network": "64500",
        "rir": "arin",
        "country": "MA",
        "detail_time": (
            "2026-07-13T11:12:10+00:00"
        ),
    }


def test_creates_cidr_indicator(
    complete_raw_record: Dict[str, Any],
) -> None:
    source, _ = create_source()

    threat = source.parse(
        [complete_raw_record]
    )[0]

    indicator = find_indicator(
        threat,
        indicator_type="cidr",
        value="192.0.2.0/24",
    )

    assert indicator.confidence == 1.0
    assert indicator.metadata["country"] == "MA"
    assert indicator.metadata["rir"] == "arin"


def test_creates_ipv6_indicator_from_details() -> None:
    raw_record = {
        "phish_id": 103,
        "url": "https://ipv6.example.invalid/login",
        "verified": "yes",
        "online": "yes",
        "details": [
            {
                "ip_address": "2001:db8::20",
                "country": "MA",
            }
        ],
    }

    source, _ = create_source()

    threat = source.parse(
        [raw_record]
    )[0]

    indicator = find_indicator(
        threat,
        indicator_type="ipv6",
        value="2001:db8::20",
    )

    assert indicator.metadata["country"] == "MA"


def test_invalid_ip_address_is_not_mapped() -> None:
    raw_record = {
        "phish_id": 104,
        "url": "https://invalid-ip.example.invalid/login",
        "verified": "yes",
        "online": "yes",
        "details": [
            {
                "ip_address": "not-an-ip-address",
            }
        ],
    }

    source, _ = create_source()

    threat = source.parse(
        [raw_record]
    )[0]

    values = {
        indicator.value
        for indicator in threat.indicators
    }

    assert "not-an-ip-address" not in values


def test_invalid_details_type_is_ignored() -> None:
    raw_record = {
        "phish_id": 105,
        "url": "https://details.example.invalid/login",
        "verified": "yes",
        "online": "yes",
        "details": "invalid-details",
    }

    source, _ = create_source()

    threat = source.parse(
        [raw_record]
    )[0]

    indicator_types = {
        indicator.type
        for indicator in threat.indicators
    }

    assert indicator_types == {
        "url",
        "domain",
    }


def test_non_dictionary_network_detail_is_ignored() -> None:
    raw_record = {
        "phish_id": 106,
        "url": "https://details.example.invalid/login",
        "verified": "yes",
        "online": "yes",
        "details": [
            "invalid-detail",
            None,
            123,
        ],
    }

    source, _ = create_source()

    threat = source.parse(
        [raw_record]
    )[0]

    assert len(threat.indicators) == 2


# ============================================================
# Correct metadata behavior
# ============================================================


def test_false_status_values_are_preserved_in_metadata() -> None:
    raw_record = {
        "phish_id": 107,
        "url": "https://offline.example.invalid/login",
        "verified": "no",
        "online": "no",
        "details": [
            {
                "ip_address": "192.0.2.80",
            }
        ],
    }

    source, _ = create_source()

    threat = source.parse(
        [raw_record]
    )[0]

    url_indicator = find_indicator(
        threat,
        indicator_type="url",
    )

    ip_indicator = find_indicator(
        threat,
        indicator_type="ipv4",
    )

    assert url_indicator.confidence is None
    assert ip_indicator.confidence is None

    assert url_indicator.metadata == {
        "source": "PHISHTANK",
        "verified": False,
        "online": False,
    }

    assert ip_indicator.metadata == {
        "source": "PHISHTANK",
        "verified": False,
        "online": False,
    }

    assert "unverified" in threat.labels
    assert "offline" in threat.labels


def test_unknown_status_values_are_omitted_from_metadata() -> None:
    raw_record = {
        "phish_id": 108,
        "url": "https://unknown.example.invalid/login",
        "verified": "unknown",
        "online": None,
        "details": [],
    }

    source, _ = create_source()

    threat = source.parse(
        [raw_record]
    )[0]

    url_indicator = find_indicator(
        threat,
        indicator_type="url",
    )

    assert url_indicator.confidence is None

    assert url_indicator.metadata == {
        "source": "PHISHTANK",
    }

    assert "verified" not in url_indicator.metadata
    assert "online" not in url_indicator.metadata

    assert "verified" not in threat.labels
    assert "unverified" not in threat.labels
    assert "online" not in threat.labels
    assert "offline" not in threat.labels


def test_network_metadata_omits_missing_values() -> None:
    raw_record = {
        "phish_id": 109,
        "url": "https://minimal.example.invalid/login",
        "verified": "yes",
        "online": "yes",
        "details": [
            {
                "ip_address": "192.0.2.90",
                "country": None,
                "rir": "",
                "announcing_network": " ",
            }
        ],
    }

    source, _ = create_source()

    threat = source.parse(
        [raw_record]
    )[0]

    indicator = find_indicator(
        threat,
        indicator_type="ipv4",
    )

    assert indicator.metadata == {
        "source": "PHISHTANK",
        "verified": True,
        "online": True,
    }


# ============================================================
# Indicator deduplication
# ============================================================


def test_duplicate_network_indicators_are_removed() -> None:
    raw_record = {
        "phish_id": 110,
        "url": "https://duplicate.example.invalid/login",
        "verified": "yes",
        "online": "yes",
        "details": [
            {
                "ip_address": "192.0.2.100",
                "cidr_block": "192.0.2.0/24",
            },
            {
                "ip_address": "192.0.2.100",
                "cidr_block": "192.0.2.0/24",
            },
        ],
    }

    source, _ = create_source()

    threat = source.parse(
        [raw_record]
    )[0]

    keys = [
        (
            indicator.type,
            indicator.value,
        )
        for indicator in threat.indicators
    ]

    assert keys.count(
        ("ipv4", "192.0.2.100")
    ) == 1

    assert keys.count(
        ("cidr", "192.0.2.0/24")
    ) == 1


def test_ip_hostname_and_detail_are_deduplicated() -> None:
    raw_record = {
        "phish_id": 111,
        "url": "http://192.0.2.110/login",
        "verified": "yes",
        "online": "yes",
        "details": [
            {
                "ip_address": "192.0.2.110",
            }
        ],
    }

    source, _ = create_source()

    threat = source.parse(
        [raw_record]
    )[0]

    matching = [
        indicator
        for indicator in threat.indicators
        if (
            indicator.type == "ipv4"
            and indicator.value == "192.0.2.110"
        )
    ]

    assert len(matching) == 1


# ============================================================
# Optional and invalid records
# ============================================================


def test_record_without_details_is_supported() -> None:
    raw_record = {
        "phish_id": 112,
        "url": "https://no-details.example.invalid/login",
        "verified": "yes",
        "online": "yes",
    }

    source, _ = create_source()

    threats = source.parse(
        [raw_record]
    )

    assert len(threats) == 1
    assert len(threats[0].indicators) == 2


def test_record_without_target_is_supported() -> None:
    raw_record = {
        "phish_id": 113,
        "url": "https://no-target.example.invalid/login",
        "verified": "yes",
        "online": "yes",
        "target": None,
        "details": [],
    }

    source, _ = create_source()

    threat = source.parse(
        [raw_record]
    )[0]

    assert threat.title is not None
    assert "unknown target" in threat.title

    assert threat.description == (
        "A verified phishing URL targeting an unspecified "
        "service was reported by PhishTank and is currently "
        "online."
    )


def test_record_without_detail_url_has_no_reference() -> None:
    raw_record = {
        "phish_id": 114,
        "url": "https://no-reference.example.invalid/login",
        "verified": "yes",
        "online": "yes",
        "details": [],
    }

    source, _ = create_source()

    threat = source.parse(
        [raw_record]
    )[0]

    assert threat.references == []
    assert threat.source_urls == {}


@pytest.mark.parametrize(
    "invalid_phish_id",
    [
        None,
        "",
        "invalid",
        0,
        -1,
        True,
    ],
)
def test_invalid_phish_id_skips_record(
    invalid_phish_id: Any,
) -> None:
    raw_record = {
        "phish_id": invalid_phish_id,
        "url": "https://example.invalid/login",
    }

    source, _ = create_source()

    threats = source.parse(
        [raw_record]
    )

    assert threats == []


@pytest.mark.parametrize(
    "invalid_url",
    [
        None,
        "",
        " ",
    ],
)
def test_missing_or_empty_url_skips_record(
    invalid_url: Any,
) -> None:
    raw_record = {
        "phish_id": 115,
        "url": invalid_url,
    }

    source, _ = create_source()

    threats = source.parse(
        [raw_record]
    )

    assert threats == []


def test_parse_rejects_non_list_payload() -> None:
    source, _ = create_source()

    with pytest.raises(
        ValueError,
        match="PhishTank raw data must be a list",
    ):
        source.parse(
            {
                "phish_id": 1,
            }
        )


def test_parse_skips_non_dictionary_elements(
    complete_raw_record: Dict[str, Any],
) -> None:
    source, _ = create_source()

    threats = source.parse(
        [
            None,
            "invalid",
            123,
            complete_raw_record,
        ]
    )

    assert len(threats) == 1
    assert threats[0].id == "PHISHTANK-9477391"


def test_parse_empty_list_returns_empty_list() -> None:
    source, _ = create_source()

    assert source.parse([]) == []


# ============================================================
# Boolean normalization
# ============================================================


@pytest.mark.parametrize(
    ("raw_value", "expected"),
    [
        ("yes", True),
        ("YES", True),
        (" y ", True),
        ("true", True),
        ("1", True),
        (True, True),
        ("no", False),
        ("NO", False),
        (" n ", False),
        ("false", False),
        ("0", False),
        (False, False),
        ("unknown", None),
        (1, None),
        (None, None),
    ],
)
def test_normalize_boolean(
    raw_value: Any,
    expected: Optional[bool],
) -> None:
    assert (
        PhishTankThreatSource._normalize_boolean(
            raw_value
        )
        is expected
    )


# ============================================================
# IP detection
# ============================================================


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("192.0.2.1", "ipv4"),
        ("255.255.255.255", "ipv4"),
        ("2001:db8::1", "ipv6"),
        ("::1", "ipv6"),
        ("invalid", None),
        ("999.999.999.999", None),
        ("example.com", None),
    ],
)
def test_detect_ip_type(
    value: str,
    expected: Optional[str],
) -> None:
    assert (
        PhishTankThreatSource._detect_ip_type(
            value
        )
        == expected
    )


# ============================================================
# collect and CollectionResult
# ============================================================


def test_collect_returns_collection_result(
    complete_raw_record: Dict[str, Any],
    sync_state: Dict[str, Any],
) -> None:
    source, connector = create_source(
        records=[complete_raw_record],
        state=sync_state,
    )

    result = source.collect()

    assert isinstance(result, CollectionResult)
    assert len(result.threats) == 1
    assert result.threats[0].id == (
        "PHISHTANK-9477391"
    )

    assert connector.state_calls == 1


def test_collect_returns_expected_metadata(
    complete_raw_record: Dict[str, Any],
    sync_state: Dict[str, Any],
) -> None:
    source, _ = create_source(
        records=[complete_raw_record],
        state=sync_state,
        limit=10,
        force_download=True,
    )

    result = source.collect()

    assert result.metadata == {
        "source": "PHISHTANK",
        "category": ThreatCategory.PHISHING.value,
        "raw_record_count": 1,
        "threat_count": 1,
        "skipped_record_count": 0,
        "limit": 10,
        "force_download": True,
        "verified_only": True,
        "online_only": True,
        "etag": '"etag-123"',
        "last_modified": (
            "Mon, 13 Jul 2026 12:23:00 GMT"
        ),
        "content_length": 2840000,
        "downloaded_at": (
            "2026-07-13T13:45:47+00:00"
        ),
        "dump_path": (
            "data/phishtank/online-valid.json.bz2"
        ),
        "downloaded": True,
        "used_local_snapshot": False,
    }


def test_collect_reports_skipped_records(
    complete_raw_record: Dict[str, Any],
) -> None:
    invalid_record = {
        "phish_id": None,
        "url": None,
    }

    source, _ = create_source(
        records=[
            complete_raw_record,
            invalid_record,
        ],
    )

    result = source.collect()

    assert result.metadata["raw_record_count"] == 2
    assert result.metadata["threat_count"] == 1
    assert result.metadata["skipped_record_count"] == 1


def test_collect_with_empty_connector_result() -> None:
    source, _ = create_source(
        records=[],
        state={},
    )

    result = source.collect()

    assert result.threats == []

    assert result.metadata["raw_record_count"] == 0
    assert result.metadata["threat_count"] == 0
    assert result.metadata["skipped_record_count"] == 0


def test_collect_handles_empty_sync_state(
    complete_raw_record: Dict[str, Any],
) -> None:
    source, _ = create_source(
        records=[complete_raw_record],
        state={},
    )

    result = source.collect()

    assert result.metadata["etag"] is None
    assert result.metadata["last_modified"] is None
    assert result.metadata["content_length"] is None
    assert result.metadata["downloaded_at"] is None
    assert result.metadata["dump_path"] is None
    assert result.metadata["downloaded"] is None
    assert result.metadata["used_local_snapshot"] is None
