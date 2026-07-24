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
    )

    assert len(result.records) == 1
    assert result.records[0].source_url is None

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
        )

def test_constructor_rejects_missing_connector() -> None:
    with pytest.raises(
        ValueError,
        match="must not be None",
    ):
        GitHubAdvisoryIngestionConnector(
            connector=None,  # type: ignore[arg-type]
        )