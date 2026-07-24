from __future__ import annotations

from typing import Any
from datetime import UTC, datetime, timedelta

from application.ports.outbound.ingestion_connector import (
    FetchedRecord,
    FetchResult,
)
from infrastructure.adapters.outbound.github_advisory_connector import (
    GitHubAdvisoryConnector,
)


class GitHubAdvisoryIngestionConnector:
    VERSION = "1.0.0"
    HIGH_WATER_MARK_OVERLAP = timedelta(
        minutes=5,
    )

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
        state_metadata: dict[str, Any] | None = None,
    ) -> FetchResult:
        previous_high_water_mark = (
            self._extract_high_water_mark(
                state_metadata
            )
        )

        modified_filter = self._resolve_modified_filter(
            cursor=cursor,
            high_water_mark=previous_high_water_mark,
        )

        page = self._connector.fetch_advisory_page(
            after=cursor,
            advisory_type=self._advisory_type,
            ecosystem=self._ecosystem,
            severity=self._severity,
            modified=modified_filter,
            per_page=self._per_page,
        )

        records: list[FetchedRecord] = []

        candidate_high_water_mark = (
            self._extract_candidate_high_water_mark(
                advisories=page.advisories,
                previous_candidate=self._extract_candidate(
                    state_metadata
                ),
            )
        )

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

        metadata = self._build_metadata(
            records_count=len(records),
            next_cursor=page.next_cursor,
            previous_high_water_mark=previous_high_water_mark,
            candidate_high_water_mark=(
                candidate_high_water_mark
            ),
        )

        return FetchResult(
            records=records,
            next_cursor=page.next_cursor,
            metadata=metadata,
            connector_version=self.VERSION,
        )
        
    
    @staticmethod
    def _extract_high_water_mark(
        state_metadata: dict[str, Any] | None,
    ) -> str | None:
        if not state_metadata:
            return None

        value = state_metadata.get(
            "high_water_mark"
        )

        if not isinstance(value, str):
            return None

        normalized = value.strip()

        return normalized or None


    @staticmethod
    def _extract_candidate(
        state_metadata: dict[str, Any] | None,
    ) -> str | None:
        if not state_metadata:
            return None

        value = state_metadata.get(
            "candidate_high_water_mark"
        )

        if not isinstance(value, str):
            return None

        normalized = value.strip()

        return normalized or None
    
    
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
    
    @classmethod
    def _resolve_modified_filter(
        cls,
        *,
        cursor: str | None,
        high_water_mark: str | None,
    ) -> str | None:
        if cursor is not None:
            return None

        if high_water_mark is None:
            return None

        parsed = cls._parse_github_datetime(
            high_water_mark
        )

        overlapped = (
            parsed
            - cls.HIGH_WATER_MARK_OVERLAP
        )

        return f">={cls._format_github_datetime(overlapped)}"
    
    
    @classmethod
    def _extract_candidate_high_water_mark(
        cls,
        *,
        advisories: list[dict[str, Any]],
        previous_candidate: str | None,
    ) -> str | None:
        candidates: list[datetime] = []

        if previous_candidate is not None:
            candidates.append(
                cls._parse_github_datetime(
                    previous_candidate
                )
            )

        for advisory in advisories:
            updated_at = advisory.get(
                "updated_at"
            )

            if not isinstance(updated_at, str):
                continue

            try:
                parsed = cls._parse_github_datetime(
                    updated_at
                )
            except ValueError:
                continue

            candidates.append(parsed)

        if not candidates:
            return previous_candidate

        return cls._format_github_datetime(
            max(candidates)
        )
    
    
    @staticmethod
    def _parse_github_datetime(
        value: str,
    ) -> datetime:
        normalized = value.strip()

        if normalized.endswith("Z"):
            normalized = (
                normalized[:-1]
                + "+00:00"
            )

        parsed = datetime.fromisoformat(
            normalized
        )

        if parsed.tzinfo is None:
            parsed = parsed.replace(
                tzinfo=UTC
            )

        return parsed.astimezone(UTC)


    @staticmethod
    def _format_github_datetime(
        value: datetime,
    ) -> str:
        normalized = value.astimezone(
            UTC
        ).replace(
            microsecond=0
        )

        return (
            normalized.isoformat()
            .replace(
                "+00:00",
                "Z",
            )
        )
    
    
    def _build_metadata(
        self,
        *,
        records_count: int,
        next_cursor: str | None,
        previous_high_water_mark: str | None,
        candidate_high_water_mark: str | None,
    ) -> dict[str, Any]:
        metadata: dict[str, Any] = {
            "source": "github_advisory",
            "advisory_type": self._advisory_type,
            "ecosystem": self._ecosystem,
            "severity": self._severity,
            "modified": self._modified,
            "per_page": self._per_page,
            "records_count": records_count,
            "pagination_complete": (
                next_cursor is None
            ),
        }

        if next_cursor is None:
            if candidate_high_water_mark is not None:
                metadata["high_water_mark"] = (
                    candidate_high_water_mark
                )
        else:
            if previous_high_water_mark is not None:
                metadata["high_water_mark"] = (
                    previous_high_water_mark
                )

            if candidate_high_water_mark is not None:
                metadata[
                    "candidate_high_water_mark"
                ] = candidate_high_water_mark

        return metadata