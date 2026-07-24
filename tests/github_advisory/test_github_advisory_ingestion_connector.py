from unittest.mock import Mock

import pytest

from infrastructure.adapters.outbound.github.github_advisory_ingestion_connector import (
    GitHubAdvisoryIngestionConnector,
)
from infrastructure.adapters.outbound.github_advisory_connector import (
    GitHubAdvisoryPage,
)


def test_fetch_maps_github_page_to_fetch_result() -> None:
    connector = Mock()

    connector.fetch_advisory_page.return_value = (
        GitHubAdvisoryPage(
            advisories=[
                {
                    "ghsa_id": "GHSA-1234-5678-9012",
                    "cve_id": "CVE-2026-0001",
                    "html_url": (
                        "https://github.com/advisories/"
                        "GHSA-1234-5678-9012"
                    ),
                    "summary": "Test advisory",
                }
            ],
            next_cursor="cursor-page-2",
        )
    )

    adapter = GitHubAdvisoryIngestionConnector(
        connector=connector,
        advisory_type="reviewed",
        ecosystem="pip",
        severity="high",
        per_page=50,
    )

    result = adapter.fetch(
        cursor="cursor-page-1",
        state_metadata=None,
    )

    connector.fetch_advisory_page.assert_called_once_with(
        after="cursor-page-1",
        advisory_type="reviewed",
        ecosystem="pip",
        severity="high",
        modified=None,
        per_page=50,
    )

    assert len(result.records) == 1

    record = result.records[0]

    assert (
        record.external_record_id
        == "GHSA-1234-5678-9012"
    )
    assert record.payload["cve_id"] == "CVE-2026-0001"
    assert record.http_status == 200
    assert (
        record.source_url
        == (
            "https://github.com/advisories/"
            "GHSA-1234-5678-9012"
        )
    )

    assert result.next_cursor == "cursor-page-2"
    assert result.connector_version == "1.0.0"
    assert result.metadata["records_count"] == 1
    assert result.metadata["ecosystem"] == "pip"
    assert result.metadata["pagination_complete"] is False


def test_fetch_accepts_advisory_without_html_url() -> None:
    connector = Mock()

    connector.fetch_advisory_page.return_value = (
        GitHubAdvisoryPage(
            advisories=[
                {
                    "ghsa_id": "GHSA-1111-2222-3333",
                }
            ],
            next_cursor=None,
        )
    )

    adapter = GitHubAdvisoryIngestionConnector(
        connector=connector,
    )

    result = adapter.fetch(
        cursor=None,
        state_metadata=None,
    )

    assert len(result.records) == 1
    assert result.records[0].source_url is None
    assert result.next_cursor is None
    assert result.metadata["pagination_complete"] is True


@pytest.mark.parametrize(
    "invalid_ghsa_id",
    [
        None,
        "",
        "   ",
        123,
    ],
)
def test_fetch_rejects_advisory_without_valid_ghsa_id(
    invalid_ghsa_id: object,
) -> None:
    connector = Mock()

    connector.fetch_advisory_page.return_value = (
        GitHubAdvisoryPage(
            advisories=[
                {
                    "ghsa_id": invalid_ghsa_id,
                }
            ],
            next_cursor=None,
        )
    )

    adapter = GitHubAdvisoryIngestionConnector(
        connector=connector,
    )

    with pytest.raises(
        ValueError,
        match="missing a valid ghsa_id",
    ):
        adapter.fetch(
            cursor=None,
            state_metadata=None,
        )


def test_constructor_rejects_missing_connector() -> None:
    with pytest.raises(
        ValueError,
        match="must not be None",
    ):
        GitHubAdvisoryIngestionConnector(
            connector=None,  # type: ignore[arg-type]
        )


def test_fetch_continues_existing_pagination_without_modified_filter() -> None:
    connector = Mock()

    connector.fetch_advisory_page.return_value = (
        GitHubAdvisoryPage(
            advisories=[
                {
                    "ghsa_id": "GHSA-1111-2222-3333",
                    "updated_at": "2026-07-24T10:20:00Z",
                }
            ],
            next_cursor="cursor-page-3",
        )
    )

    adapter = GitHubAdvisoryIngestionConnector(
        connector=connector,
    )

    result = adapter.fetch(
        cursor="cursor-page-2",
        state_metadata={
            "high_water_mark": (
                "2026-07-24T10:00:00Z"
            ),
            "candidate_high_water_mark": (
                "2026-07-24T10:15:00Z"
            ),
        },
    )

    connector.fetch_advisory_page.assert_called_once_with(
        after="cursor-page-2",
        advisory_type="reviewed",
        ecosystem=None,
        severity=None,
        modified=None,
        per_page=100,
    )

    assert result.next_cursor == "cursor-page-3"
    assert result.metadata["pagination_complete"] is False
    assert (
        result.metadata["high_water_mark"]
        == "2026-07-24T10:00:00Z"
    )
    assert (
        result.metadata["candidate_high_water_mark"]
        == "2026-07-24T10:20:00Z"
    )


def test_fetch_starts_incremental_cycle_from_high_water_mark() -> None:
    connector = Mock()

    connector.fetch_advisory_page.return_value = (
        GitHubAdvisoryPage(
            advisories=[
                {
                    "ghsa_id": "GHSA-2222-3333-4444",
                    "updated_at": "2026-07-24T10:10:00Z",
                }
            ],
            next_cursor="cursor-page-2",
        )
    )

    adapter = GitHubAdvisoryIngestionConnector(
        connector=connector,
    )

    result = adapter.fetch(
        cursor=None,
        state_metadata={
            "high_water_mark": (
                "2026-07-24T10:00:00Z"
            ),
        },
    )

    connector.fetch_advisory_page.assert_called_once_with(
        after=None,
        advisory_type="reviewed",
        ecosystem=None,
        severity=None,
        modified=">=2026-07-24T09:55:00Z",
        per_page=100,
    )

    assert result.next_cursor == "cursor-page-2"
    assert result.metadata["pagination_complete"] is False
    assert (
        result.metadata["high_water_mark"]
        == "2026-07-24T10:00:00Z"
    )
    assert (
        result.metadata["candidate_high_water_mark"]
        == "2026-07-24T10:10:00Z"
    )


def test_fetch_promotes_candidate_on_last_page() -> None:
    connector = Mock()

    connector.fetch_advisory_page.return_value = (
        GitHubAdvisoryPage(
            advisories=[
                {
                    "ghsa_id": "GHSA-3333-4444-5555",
                    "updated_at": "2026-07-24T10:35:00Z",
                }
            ],
            next_cursor=None,
        )
    )

    adapter = GitHubAdvisoryIngestionConnector(
        connector=connector,
    )

    result = adapter.fetch(
        cursor="cursor-last-page",
        state_metadata={
            "high_water_mark": (
                "2026-07-24T10:00:00Z"
            ),
            "candidate_high_water_mark": (
                "2026-07-24T10:20:00Z"
            ),
        },
    )

    assert result.next_cursor is None
    assert result.metadata["pagination_complete"] is True
    assert (
        result.metadata["high_water_mark"]
        == "2026-07-24T10:35:00Z"
    )
    assert (
        "candidate_high_water_mark"
        not in result.metadata
    )


def test_fetch_keeps_previous_candidate_when_it_is_newer() -> None:
    connector = Mock()

    connector.fetch_advisory_page.return_value = (
        GitHubAdvisoryPage(
            advisories=[
                {
                    "ghsa_id": "GHSA-4444-5555-6666",
                    "updated_at": "2026-07-24T10:20:00Z",
                }
            ],
            next_cursor="cursor-next",
        )
    )

    adapter = GitHubAdvisoryIngestionConnector(
        connector=connector,
    )

    result = adapter.fetch(
        cursor="cursor-current",
        state_metadata={
            "high_water_mark": (
                "2026-07-24T10:00:00Z"
            ),
            "candidate_high_water_mark": (
                "2026-07-24T10:30:00Z"
            ),
        },
    )

    assert (
        result.metadata["candidate_high_water_mark"]
        == "2026-07-24T10:30:00Z"
    )


def test_fetch_ignores_invalid_updated_at() -> None:
    connector = Mock()

    connector.fetch_advisory_page.return_value = (
        GitHubAdvisoryPage(
            advisories=[
                {
                    "ghsa_id": "GHSA-5555-6666-7777",
                    "updated_at": "invalid-date",
                }
            ],
            next_cursor="cursor-next",
        )
    )

    adapter = GitHubAdvisoryIngestionConnector(
        connector=connector,
    )

    result = adapter.fetch(
        cursor="cursor-current",
        state_metadata={
            "high_water_mark": (
                "2026-07-24T10:00:00Z"
            ),
            "candidate_high_water_mark": (
                "2026-07-24T10:15:00Z"
            ),
        },
    )

    assert result.metadata["pagination_complete"] is False
    assert (
        result.metadata["candidate_high_water_mark"]
        == "2026-07-24T10:15:00Z"
    )

