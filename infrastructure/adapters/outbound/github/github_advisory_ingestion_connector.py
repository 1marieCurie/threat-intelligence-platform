from __future__ import annotations

from typing import Any

from application.ports.outbound.ingestion_connector import (
    FetchedRecord,
    FetchResult,
)
from infrastructure.adapters.outbound.github_advisory_connector import (
    GitHubAdvisoryConnector,
)


class GitHubAdvisoryIngestionConnector:
    VERSION = "1.0.0"

    def __init__(
        self,
        *,
        connector: GitHubAdvisoryConnector,
        advisory_type: str = "reviewed",
        ecosystem: str | None = None,
        severity: str | None = None,
        modified: str | None = None,
        per_page: int = 100,
    ) -> None:
        if connector is None:
            raise ValueError(
                "GitHub Advisory connector must not be None."
            )

        self._connector = connector
        self._advisory_type = advisory_type
        self._ecosystem = ecosystem
        self._severity = severity
        self._modified = modified
        self._per_page = per_page

    def fetch(
        self,
        *,
        cursor: str | None,
    ) -> FetchResult:
        page = self._connector.fetch_advisory_page(
            after=cursor,
            advisory_type=self._advisory_type,
            ecosystem=self._ecosystem,
            severity=self._severity,
            modified=self._modified,
            per_page=self._per_page,
        )

        records: list[FetchedRecord] = []

        for advisory in page.advisories:
            external_record_id = (
                self._extract_external_record_id(
                    advisory
                )
            )

            records.append(
                FetchedRecord(
                    external_record_id=external_record_id,
                    payload=advisory,
                    source_url=self._extract_source_url(
                        advisory
                    ),
                    http_status=200,
                )
            )

        return FetchResult(
            records=records,
            next_cursor=page.next_cursor,
            metadata={
                "source": "github_advisory",
                "advisory_type": self._advisory_type,
                "ecosystem": self._ecosystem,
                "severity": self._severity,
                "modified": self._modified,
                "per_page": self._per_page,
                "records_count": len(records),
            },
            connector_version=self.VERSION,
        )

    @staticmethod
    def _extract_external_record_id(
        advisory: dict[str, Any],
    ) -> str:
        ghsa_id = advisory.get("ghsa_id")

        if not isinstance(ghsa_id, str):
            raise ValueError(
                "GitHub advisory is missing a valid ghsa_id."
            )

        normalized_ghsa_id = ghsa_id.strip()

        if not normalized_ghsa_id:
            raise ValueError(
                "GitHub advisory is missing a valid ghsa_id."
            )

        return normalized_ghsa_id

    @staticmethod
    def _extract_source_url(
        advisory: dict[str, Any],
    ) -> str | None:
        html_url = advisory.get("html_url")

        if not isinstance(html_url, str):
            return None

        normalized_url = html_url.strip()

        return normalized_url or None