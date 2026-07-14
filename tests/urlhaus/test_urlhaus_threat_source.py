from __future__ import annotations

from typing import Any, Dict, List, Optional

import pytest

from application.services.urlhaus_threat_source import (
    URLhausThreatSource,
)
from domain.collection_result import CollectionResult
from domain.indicator import Indicator
from domain.threat import Threat
from infrastructure.adapters.outbound.urlhaus_connector import (
    URLhausConnector,
)


# ============================================================
# Fake connector
# ============================================================


class FakeURLhausConnector(URLhausConnector):
    """
    Fake URLhaus connector used to test the application service
    without performing real HTTP requests.
    """

    def __init__(
        self,
        *,
        recent_response: Optional[Dict[str, Any]] = None,
        detail_responses: Optional[
            Dict[str, Dict[str, Any]]
        ] = None,
        detail_exception: Optional[Exception] = None,
    ) -> None:
        self.recent_response = (
            recent_response
            if recent_response is not None
            else {
                "query_status": "ok",
                "urls": [],
            }
        )

        self.detail_responses = detail_responses or {}
        self.detail_exception = detail_exception

        self.recent_calls: List[Dict[str, Any]] = []
        self.detail_calls: List[str] = []

    def fetch_recent_urls(
        self,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        self.recent_calls.append(
            {
                "limit": limit,
            }
        )

        return self.recent_response

    def fetch_url_information_by_id(
        self,
        urlhaus_id: str | int,
    ) -> Dict[str, Any]:
        normalized_id = str(urlhaus_id)

        self.detail_calls.append(normalized_id)

        if self.detail_exception is not None:
            raise self.detail_exception

        return self.detail_responses.get(
            normalized_id,
            {
                "query_status": "no_results",
            },
        )


# ============================================================
# Fixtures
# ============================================================


@pytest.fixture
def recent_url_entry() -> Dict[str, Any]:
    return {
        "id": 3886372,
        "urlhaus_reference": (
            "https://urlhaus.abuse.ch/url/3886372/"
        ),
        "url": "http://59.180.140.134/malware",
        "url_status": "online",
        "host": "59.180.140.134",
        "date_added": "2026-07-14 11:21:22 UTC",
        "threat": "malware_download",
        "blacklists": {
            "spamhaus_dbl": "not listed",
            "surbl": "not listed",
        },
        "reporter": "example-reporter",
        "larted": "true",
        "tags": [
            "32-bit",
            "elf",
            "mips",
            "Mozi",
        ],
    }


@pytest.fixture
def recent_response(
    recent_url_entry: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        "query_status": "ok",
        "urls": [
            recent_url_entry,
        ],
    }


@pytest.fixture
def detailed_response(
    recent_url_entry: Dict[str, Any],
) -> Dict[str, Any]:
    return {
        **recent_url_entry,
        "query_status": "ok",
        "last_online": None,
        "takedown_time_seconds": None,
        "payloads": [
            {
                "firstseen": "2026-07-14",
                "filename": "malware",
                "file_type": "elf",
                "response_size": "123456",
                "response_md5": "a" * 32,
                "response_sha256": "b" * 64,
                "urlhaus_download": (
                    "https://urlhaus-api.abuse.ch/"
                    "v1/download/bbbbb/"
                ),
                "signature": "Mozi",
                "virustotal": {
                    "result": "20 / 70",
                    "percent": "28.57",
                    "link": "https://example.test/vt",
                },
                "imphash": None,
                "ssdeep": "3:abc:def",
                "tlsh": "T1ABCDEF",
                "magika": "elf",
            }
        ],
    }


# ============================================================
# Initialization and source identity
# ============================================================


def test_source_name_is_urlhaus() -> None:
    source = URLhausThreatSource(
        connector=FakeURLhausConnector()
    )

    assert source.name == "URLHAUS"


@pytest.mark.parametrize(
    "max_detail_requests",
    [
        0,
        -1,
        1.5,
        "5",
        True,
        False,
    ],
)
def test_init_rejects_invalid_max_detail_requests(
    max_detail_requests: Any,
) -> None:
    with pytest.raises(
        ValueError,
        match="max_detail_requests",
    ):
        URLhausThreatSource(
            connector=FakeURLhausConnector(),
            max_detail_requests=max_detail_requests,
        )


def test_init_accepts_none_max_detail_requests() -> None:
    source = URLhausThreatSource(
        connector=FakeURLhausConnector(),
        max_detail_requests=None,
    )

    assert source is not None


def test_init_accepts_positive_max_detail_requests() -> None:
    source = URLhausThreatSource(
        connector=FakeURLhausConnector(),
        max_detail_requests=5,
    )

    assert source is not None


# ============================================================
# fetch_raw
# ============================================================


def test_fetch_raw_delegates_to_connector(
    recent_response: Dict[str, Any],
) -> None:
    connector = FakeURLhausConnector(
        recent_response=recent_response
    )

    source = URLhausThreatSource(
        connector=connector,
        limit=25,
    )

    result = source.fetch_raw()

    assert result == recent_response
    assert connector.recent_calls == [
        {
            "limit": 25,
        }
    ]


def test_fetch_raw_passes_none_limit() -> None:
    connector = FakeURLhausConnector()

    source = URLhausThreatSource(
        connector=connector,
        limit=None,
    )

    source.fetch_raw()

    assert connector.recent_calls == [
        {
            "limit": None,
        }
    ]


# ============================================================
# Parsing basic records
# ============================================================


def test_parse_complete_urlhaus_entry(
    recent_response: Dict[str, Any],
) -> None:
    source = URLhausThreatSource(
        connector=FakeURLhausConnector()
    )

    threats = source.parse(recent_response)

    assert len(threats) == 1

    threat = threats[0]

    assert isinstance(threat, Threat)

    assert threat.id == "URLHAUS-3886372"

    assert threat.external_ids == {
        "URLHAUS": ["3886372"],
    }

    assert threat.title == (
        "Mozi malware distribution from "
        "59.180.140.134"
    )

    assert threat.advisory_type == (
        "malware_download"
    )

    assert threat.threat_type == (
        "malware_distribution"
    )

    assert threat.source == "URLHAUS"

    assert threat.labels == [
        "32-bit",
        "elf",
        "mips",
        "Mozi",
    ]

    assert threat.references == [
        "https://urlhaus.abuse.ch/url/3886372/"
    ]

    assert threat.source_urls == {
        "URLHAUS": (
            "https://urlhaus.abuse.ch/url/3886372/"
        )
    }

    assert threat.source_dates == {
        "date_added": (
            "2026-07-14 11:21:22 UTC"
        ),
        "first_seen": (
            "2026-07-14 11:21:22 UTC"
        ),
    }

    assert threat.raw == recent_response["urls"][0]


def test_parse_creates_url_and_ipv4_indicators(
    recent_response: Dict[str, Any],
) -> None:
    source = URLhausThreatSource(
        connector=FakeURLhausConnector()
    )

    threat = source.parse(recent_response)[0]

    assert len(threat.indicators) == 2

    url_indicator = next(
        indicator
        for indicator in threat.indicators
        if indicator.type == "url"
    )

    ipv4_indicator = next(
        indicator
        for indicator in threat.indicators
        if indicator.type == "ipv4"
    )

    assert url_indicator.value == (
        "http://59.180.140.134/malware"
    )

    assert url_indicator.metadata == {
        "source": "URLHAUS",
        "urlhaus_id": "3886372",
        "status": "online",
        "first_seen": (
            "2026-07-14 11:21:22 UTC"
        ),
        "reporter": "example-reporter",
        "provider_notified": True,
        "blacklists": {
            "spamhaus_dbl": "not listed",
            "surbl": "not listed",
        },
        "tags": [
            "32-bit",
            "elf",
            "mips",
            "Mozi",
        ],
    }

    assert ipv4_indicator.value == "59.180.140.134"

    assert ipv4_indicator.metadata == {
        "source": "URLHAUS",
        "urlhaus_id": "3886372",
    }


def test_parse_creates_domain_indicator() -> None:
    raw_data = {
        "query_status": "ok",
        "urls": [
            {
                "id": 10,
                "url": (
                    "http://malware.example.test/file"
                ),
                "host": "malware.example.test",
                "url_status": "online",
                "threat": "malware_download",
                "tags": [],
            }
        ],
    }

    source = URLhausThreatSource(
        connector=FakeURLhausConnector()
    )

    threat = source.parse(raw_data)[0]

    indicator_types = {
        indicator.type
        for indicator in threat.indicators
    }

    assert indicator_types == {
        "url",
        "domain",
    }


def test_parse_creates_ipv6_indicator() -> None:
    raw_data = {
        "query_status": "ok",
        "urls": [
            {
                "id": 11,
                "url": "http://[2001:db8::10]/file",
                "host": "2001:db8::10",
                "url_status": "online",
                "threat": "malware_download",
                "tags": [],
            }
        ],
    }

    source = URLhausThreatSource(
        connector=FakeURLhausConnector()
    )

    threat = source.parse(raw_data)[0]

    indicator_types = {
        indicator.type
        for indicator in threat.indicators
    }

    assert indicator_types == {
        "url",
        "ipv6",
    }


def test_parse_extracts_host_from_url_when_missing() -> None:
    raw_data = {
        "query_status": "ok",
        "urls": [
            {
                "id": 12,
                "url": (
                    "http://malware.example.test/file"
                ),
                "url_status": "online",
                "threat": "malware_download",
                "tags": [],
            }
        ],
    }

    source = URLhausThreatSource(
        connector=FakeURLhausConnector()
    )

    threat = source.parse(raw_data)[0]

    domain_indicator = next(
        indicator
        for indicator in threat.indicators
        if indicator.type == "domain"
    )

    assert domain_indicator.value == (
        "malware.example.test"
    )


def test_parse_preserves_url_when_host_is_unavailable() -> None:
    raw_data = {
        "query_status": "ok",
        "urls": [
            {
                "id": 13,
                "url": "not-a-standard-url",
                "url_status": "online",
                "threat": "malware_download",
                "tags": [],
            }
        ],
    }

    source = URLhausThreatSource(
        connector=FakeURLhausConnector()
    )

    threat = source.parse(raw_data)[0]

    assert len(threat.indicators) == 1
    assert threat.indicators[0].type == "url"
    assert threat.indicators[0].value == (
        "not-a-standard-url"
    )


# ============================================================
# Invalid and partial input
# ============================================================


@pytest.mark.parametrize(
    "raw_data",
    [
        None,
        [],
        "invalid",
        123,
    ],
)
def test_parse_rejects_non_dictionary_root(
    raw_data: Any,
) -> None:
    source = URLhausThreatSource(
        connector=FakeURLhausConnector()
    )

    assert source.parse(raw_data) == []


@pytest.mark.parametrize(
    "raw_data",
    [
        {},
        {
            "query_status": "no_results",
        },
        {
            "query_status": "error",
            "urls": [],
        },
        {
            "query_status": "ok",
        },
        {
            "query_status": "ok",
            "urls": None,
        },
        {
            "query_status": "ok",
            "urls": {},
        },
    ],
)
def test_parse_returns_empty_for_invalid_response(
    raw_data: Dict[str, Any],
) -> None:
    source = URLhausThreatSource(
        connector=FakeURLhausConnector()
    )

    assert source.parse(raw_data) == []


def test_parse_ignores_non_dictionary_elements(
    recent_url_entry: Dict[str, Any],
) -> None:
    raw_data = {
        "query_status": "ok",
        "urls": [
            None,
            "invalid",
            123,
            [],
            recent_url_entry,
        ],
    }

    source = URLhausThreatSource(
        connector=FakeURLhausConnector()
    )

    threats = source.parse(raw_data)

    assert len(threats) == 1
    assert threats[0].id == "URLHAUS-3886372"


@pytest.mark.parametrize(
    "entry",
    [
        {
            "url": "http://example.test/file",
        },
        {
            "id": 10,
        },
        {
            "id": True,
            "url": "http://example.test/file",
        },
        {
            "id": -1,
            "url": "http://example.test/file",
        },
        {
            "id": "ABC",
            "url": "http://example.test/file",
        },
        {
            "id": 10,
            "url": "",
        },
        {
            "id": 10,
            "url": None,
        },
    ],
)
def test_parse_skips_entries_without_required_fields(
    entry: Dict[str, Any],
) -> None:
    raw_data = {
        "query_status": "ok",
        "urls": [entry],
    }

    source = URLhausThreatSource(
        connector=FakeURLhausConnector()
    )

    assert source.parse(raw_data) == []


def test_parse_accepts_string_identifier() -> None:
    raw_data = {
        "query_status": "ok",
        "urls": [
            {
                "id": "12345",
                "url": "http://example.test/file",
            }
        ],
    }

    source = URLhausThreatSource(
        connector=FakeURLhausConnector()
    )

    threat = source.parse(raw_data)[0]

    assert threat.id == "URLHAUS-12345"
    assert threat.external_ids == {
        "URLHAUS": ["12345"],
    }


def test_parse_normalizes_optional_fields() -> None:
    raw_data = {
        "query_status": "ok",
        "urls": [
            {
                "id": 15,
                "url": "http://example.test/file",
                "host": 123,
                "tags": [
                    " elf ",
                    "",
                    None,
                    "ELF",
                    "Mozi",
                ],
                "blacklists": "invalid",
                "larted": "yes",
            }
        ],
    }

    source = URLhausThreatSource(
        connector=FakeURLhausConnector()
    )

    threat = source.parse(raw_data)[0]

    assert threat.labels == [
        "elf",
        "Mozi",
    ]

    url_indicator = next(
        indicator
        for indicator in threat.indicators
        if indicator.type == "url"
    )

    assert url_indicator.metadata[
        "provider_notified"
    ] is True

    assert "blacklists" not in (
        url_indicator.metadata
    )


# ============================================================
# Detailed enrichment
# ============================================================


def test_parse_without_detail_enrichment_does_not_call_details(
    recent_response: Dict[str, Any],
    detailed_response: Dict[str, Any],
) -> None:
    connector = FakeURLhausConnector(
        detail_responses={
            "3886372": detailed_response,
        }
    )

    source = URLhausThreatSource(
        connector=connector,
        enrich_with_details=False,
    )

    source.parse(recent_response)

    assert connector.detail_calls == []


def test_parse_with_details_adds_payload_indicators(
    recent_response: Dict[str, Any],
    detailed_response: Dict[str, Any],
) -> None:
    connector = FakeURLhausConnector(
        detail_responses={
            "3886372": detailed_response,
        }
    )

    source = URLhausThreatSource(
        connector=connector,
        enrich_with_details=True,
    )

    threat = source.parse(recent_response)[0]

    assert connector.detail_calls == [
        "3886372",
    ]

    indicator_types = {
        indicator.type
        for indicator in threat.indicators
    }

    assert indicator_types == {
        "url",
        "ipv4",
        "md5",
        "sha256",
    }

    md5_indicator = next(
        indicator
        for indicator in threat.indicators
        if indicator.type == "md5"
    )

    sha256_indicator = next(
        indicator
        for indicator in threat.indicators
        if indicator.type == "sha256"
    )

    assert md5_indicator.value == "a" * 32
    assert sha256_indicator.value == "b" * 64

    expected_metadata = {
        "source": "URLHAUS",
        "urlhaus_id": "3886372",
        "first_seen": "2026-07-14",
        "filename": "malware",
        "file_type": "elf",
        "response_size": "123456",
        "malware_signature": "Mozi",
        "ssdeep": "3:abc:def",
        "tlsh": "T1ABCDEF",
        "magika": "elf",
        "urlhaus_download": (
            "https://urlhaus-api.abuse.ch/"
            "v1/download/bbbbb/"
        ),
        "virustotal": {
            "result": "20 / 70",
            "percent": "28.57",
            "link": "https://example.test/vt",
        },
    }

    assert md5_indicator.metadata == expected_metadata
    assert sha256_indicator.metadata == expected_metadata


def test_parse_with_details_adds_payload_labels(
    recent_response: Dict[str, Any],
    detailed_response: Dict[str, Any],
) -> None:
    connector = FakeURLhausConnector(
        detail_responses={
            "3886372": detailed_response,
        }
    )

    source = URLhausThreatSource(
        connector=connector,
        enrich_with_details=True,
    )

    threat = source.parse(recent_response)[0]

    assert threat.labels == [
        "32-bit",
        "elf",
        "mips",
        "Mozi",
    ]


def test_parse_ignores_invalid_payload_hashes(
    recent_response: Dict[str, Any],
    detailed_response: Dict[str, Any],
) -> None:
    invalid_detail_response = {
        **detailed_response,
        "payloads": [
            {
                "response_md5": "invalid",
                "response_sha256": "z" * 64,
            }
        ],
    }

    connector = FakeURLhausConnector(
        detail_responses={
            "3886372": invalid_detail_response,
        }
    )

    source = URLhausThreatSource(
        connector=connector,
        enrich_with_details=True,
    )

    threat = source.parse(recent_response)[0]

    indicator_types = {
        indicator.type
        for indicator in threat.indicators
    }

    assert indicator_types == {
        "url",
        "ipv4",
    }

def test_detail_failure_keeps_summary_record(
    recent_response: Dict[str, Any],
) -> None:
    connector = FakeURLhausConnector(
        detail_exception=RuntimeError(
            "temporary URLhaus failure"
        )
    )

    source = URLhausThreatSource(
        connector=connector,
        enrich_with_details=True,
    )

    threats = source.parse(recent_response)

    assert len(threats) == 1
    assert threats[0].id == "URLHAUS-3886372"

    assert connector.detail_calls == [
        "3886372",
    ]


def test_no_results_detail_keeps_summary_record(
    recent_response: Dict[str, Any],
) -> None:
    connector = FakeURLhausConnector(
        detail_responses={
            "3886372": {
                "query_status": "no_results",
            }
        }
    )

    source = URLhausThreatSource(
        connector=connector,
        enrich_with_details=True,
    )

    threat = source.parse(recent_response)[0]

    assert len(threat.indicators) == 2


def test_detail_request_limit_is_respected() -> None:
    raw_data = {
        "query_status": "ok",
        "urls": [
            {
                "id": 1,
                "url": "http://example.test/1",
            },
            {
                "id": 2,
                "url": "http://example.test/2",
            },
            {
                "id": 3,
                "url": "http://example.test/3",
            },
        ],
    }

    connector = FakeURLhausConnector(
        detail_responses={
            "1": {
                "query_status": "ok",
                "id": 1,
                "url": "http://example.test/1",
            },
            "2": {
                "query_status": "ok",
                "id": 2,
                "url": "http://example.test/2",
            },
            "3": {
                "query_status": "ok",
                "id": 3,
                "url": "http://example.test/3",
            },
        }
    )

    source = URLhausThreatSource(
        connector=connector,
        enrich_with_details=True,
        max_detail_requests=2,
    )

    threats = source.parse(raw_data)

    assert len(threats) == 3

    assert connector.detail_calls == [
        "1",
        "2",
    ]


def test_failed_detail_request_does_not_consume_limit() -> None:
    """
    Documents the current behavior: detail_requests is incremented
    only after a successful detail response.
    """
    raw_data = {
        "query_status": "ok",
        "urls": [
            {
                "id": 1,
                "url": "http://example.test/1",
            },
            {
                "id": 2,
                "url": "http://example.test/2",
            },
        ],
    }

    class PartiallyFailingConnector(
        FakeURLhausConnector
    ):
        def fetch_url_information_by_id(
            self,
            urlhaus_id: str | int,
        ) -> Dict[str, Any]:
            normalized_id = str(urlhaus_id)
            self.detail_calls.append(normalized_id)

            if normalized_id == "1":
                raise RuntimeError(
                    "temporary failure"
                )

            return {
                "query_status": "ok",
                "id": 2,
                "url": "http://example.test/2",
            }

    connector = PartiallyFailingConnector()

    source = URLhausThreatSource(
        connector=connector,
        enrich_with_details=True,
        max_detail_requests=1,
    )

    source.parse(raw_data)

    assert connector.detail_calls == [
        "1",
        "2",
    ]


# ============================================================
# Indicator deduplication
# ============================================================


def test_duplicate_payload_hashes_are_deduplicated() -> None:
    raw_data = {
        "query_status": "ok",
        "urls": [
            {
                "id": 20,
                "url": "http://example.test/file",
                "payloads": [
                    {
                        "response_sha256": "a" * 64,
                    },
                    {
                        "response_sha256": "a" * 64,
                    },
                ],
            }
        ],
    }

    source = URLhausThreatSource(
        connector=FakeURLhausConnector()
    )

    threat = source.parse(raw_data)[0]

    sha256_indicators = [
        indicator
        for indicator in threat.indicators
        if indicator.type == "sha256"
    ]

    assert len(sha256_indicators) == 1


def test_url_and_host_duplicate_are_kept_as_different_types() -> None:
    raw_data = {
        "query_status": "ok",
        "urls": [
            {
                "id": 21,
                "url": "http://example.test",
                "host": "example.test",
            }
        ],
    }

    source = URLhausThreatSource(
        connector=FakeURLhausConnector()
    )

    threat = source.parse(raw_data)[0]

    assert len(threat.indicators) == 2

    assert {
        indicator.type
        for indicator in threat.indicators
    } == {
        "url",
        "domain",
    }


# ============================================================
# CollectionResult
# ============================================================


def test_collect_returns_collection_result(
    recent_response: Dict[str, Any],
) -> None:
    connector = FakeURLhausConnector(
        recent_response=recent_response
    )

    source = URLhausThreatSource(
        connector=connector,
        limit=5,
    )

    result = source.collect()

    assert isinstance(result, CollectionResult)

    assert len(result.threats) == 1
    assert result.threats[0].id == (
        "URLHAUS-3886372"
    )

    assert result.metadata["source"] == "URLHAUS"
    assert result.metadata["query_status"] == "ok"
    assert result.metadata["requested_limit"] == 5
    assert result.metadata["received_records"] == 1
    assert result.metadata["parsed_threats"] == 1
    assert result.metadata["skipped_records"] == 0

    assert result.metadata[
        "details_enrichment_enabled"
    ] is False

    assert result.metadata[
        "max_detail_requests"
    ] is None

    assert isinstance(
        result.metadata["collected_at"],
        str,
    )


def test_collect_counts_skipped_records(
    recent_url_entry: Dict[str, Any],
) -> None:
    raw_response = {
        "query_status": "ok",
        "urls": [
            recent_url_entry,
            None,
            {
                "id": 99,
            },
        ],
    }

    connector = FakeURLhausConnector(
        recent_response=raw_response
    )

    source = URLhausThreatSource(
        connector=connector
    )

    result = source.collect()

    assert result.metadata["received_records"] == 3
    assert result.metadata["parsed_threats"] == 1
    assert result.metadata["skipped_records"] == 2


def test_collect_handles_no_results() -> None:
    connector = FakeURLhausConnector(
        recent_response={
            "query_status": "no_results",
        }
    )

    source = URLhausThreatSource(
        connector=connector,
        limit=5,
    )

    result = source.collect()

    assert result.threats == []

    assert result.metadata["query_status"] == (
        "no_results"
    )

    assert result.metadata["received_records"] == 0
    assert result.metadata["parsed_threats"] == 0
    assert result.metadata["skipped_records"] == 0