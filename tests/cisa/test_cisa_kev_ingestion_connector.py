from unittest.mock import Mock
from datetime import UTC

import pytest

from infrastructure.adapters.outbound.cisa_connector import (
    CISAConnector,
)
from infrastructure.adapters.outbound.cisa.cisa_kev_ingestion_connector import (
    CisaKevIngestionConnector,
)


def _build_connector(
    catalog: dict,
) -> tuple[
    CisaKevIngestionConnector,
    Mock,
]:
    cisa_connector = Mock(spec=CISAConnector)
    cisa_connector.fetch.return_value = catalog

    adapter = CisaKevIngestionConnector(
        connector=cisa_connector,
    )

    return adapter, cisa_connector


def test_fetch_maps_cisa_catalog_to_fetched_records() -> None:
    catalog = {
        "title": "CISA KEV Catalog",
        "catalogVersion": "2026.07.28",
        "dateReleased": "2026-07-28T10:00:00Z",
        "count": 2,
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-0001",
                "vendorProject": "Vendor A",
            },
            {
                "cveID": " cve-2026-0002 ",
                "vendorProject": "Vendor B",
            },
        ],
    }

    adapter, cisa_connector = _build_connector(
        catalog
    )

    result = adapter.fetch(
        cursor=None,
        state_metadata=None,
    )

    assert [
        record.external_record_id
        for record in result.records
    ] == [
        "CVE-2026-0001",
        "CVE-2026-0002",
    ]

    assert result.records[0].payload == (
        catalog["vulnerabilities"][0]
    )

    assert result.records[0].source_url == (
        CISAConnector.KEV_URL
    )

    assert result.records[0].http_status == 200
    assert result.next_cursor is None
    assert result.connector_version == "1.0.0"

    assert result.metadata == {
        "source": "cisa_kev",
        "title": "CISA KEV Catalog",
        "catalog_version": "2026.07.28",
        "date_released": "2026-07-28T10:00:00Z",
        "declared_count": 2,
        "records_count": 2,
        "pagination_complete": True,
    }
    
    assert result.records[0].fetched_at is not None
    assert (
        result.records[0].fetched_at
        == result.records[1].fetched_at
    )
    assert (
        result.records[0].fetched_at.tzinfo
        is UTC
    )

    cisa_connector.fetch.assert_called_once_with()


def test_constructor_rejects_missing_connector() -> None:
    with pytest.raises(
        ValueError,
        match="must not be None",
    ):
        CisaKevIngestionConnector(
            connector=None,  # type: ignore[arg-type]
        )


def test_fetch_rejects_cursor() -> None:
    adapter, cisa_connector = _build_connector(
        {
            "count": 0,
            "vulnerabilities": [],
        }
    )

    with pytest.raises(
        ValueError,
        match="does not support cursors",
    ):
        adapter.fetch(
            cursor="unexpected-cursor",
        )

    cisa_connector.fetch.assert_not_called()


@pytest.mark.parametrize(
    "invalid_catalog",
    [
        None,
        [],
        "invalid",
    ],
)
def test_fetch_rejects_invalid_catalog(
    invalid_catalog: object,
) -> None:
    adapter, _ = _build_connector(
        invalid_catalog  # type: ignore[arg-type]
    )

    with pytest.raises(
        ValueError,
        match="expected an object",
    ):
        adapter.fetch(
            cursor=None,
        )


def test_fetch_rejects_invalid_vulnerabilities_collection() -> None:
    adapter, _ = _build_connector(
        {
            "count": 0,
            "vulnerabilities": {},
        }
    )

    with pytest.raises(
        ValueError,
        match="must be a list",
    ):
        adapter.fetch(
            cursor=None,
        )


@pytest.mark.parametrize(
    "invalid_count",
    [
        None,
        True,
        -1,
        "2",
    ],
)
def test_fetch_rejects_invalid_count(
    invalid_count: object,
) -> None:
    adapter, _ = _build_connector(
        {
            "count": invalid_count,
            "vulnerabilities": [],
        }
    )

    with pytest.raises(
        ValueError,
        match="non-negative integer",
    ):
        adapter.fetch(
            cursor=None,
        )


def test_fetch_rejects_count_mismatch() -> None:
    adapter, _ = _build_connector(
        {
            "count": 2,
            "vulnerabilities": [
                {
                    "cveID": "CVE-2026-0001",
                }
            ],
        }
    )

    with pytest.raises(
        ValueError,
        match="does not match",
    ):
        adapter.fetch(
            cursor=None,
        )


@pytest.mark.parametrize(
    "invalid_cve_id",
    [
        None,
        "",
        "   ",
        "GHSA-aaaa-bbbb-cccc",
        123,
    ],
)
def test_fetch_rejects_invalid_cve_id(
    invalid_cve_id: object,
) -> None:
    adapter, _ = _build_connector(
        {
            "count": 1,
            "vulnerabilities": [
                {
                    "cveID": invalid_cve_id,
                }
            ],
        }
    )

    with pytest.raises(
        ValueError,
        match="cveID",
    ):
        adapter.fetch(
            cursor=None,
        )


def test_fetch_rejects_duplicate_cve_ids() -> None:
    adapter, _ = _build_connector(
        {
            "count": 2,
            "vulnerabilities": [
                {
                    "cveID": "CVE-2026-0001",
                },
                {
                    "cveID": "cve-2026-0001",
                },
            ],
        }
    )

    with pytest.raises(
        ValueError,
        match="duplicate CVE",
    ):
        adapter.fetch(
            cursor=None,
        )