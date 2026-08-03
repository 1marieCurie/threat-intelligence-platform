from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Protocol
from urllib.parse import urlsplit

from application.ports.outbound.ingestion_connector import (
    FetchedRecord,
    FetchResult,
)


class URLhausRecentURLsConnector(
    Protocol
):
    """
    Minimal provider contract required by the raw adapter.
    """

    @property
    def canonical_source_url(
        self,
    ) -> str:
        ...

    def fetch_recent_urls(
        self,
        limit: int | None = None,
    ) -> dict[str, Any]:
        ...


class URLhausIngestionConnector:
    """
    Adapt URLhaus recent URLs to the generic raw-ingestion contract.

    This adapter:

    - performs no business normalization;
    - performs no detailed enrichment request;
    - validates URLhaus record identifiers;
    - maps records to FetchedRecord;
    - exposes only allowlisted metadata.
    """

    VERSION = "1.0.0"
    SOURCE_NAME = "urlhaus"
    COLLECTION_MODE = "recent_urls"

    MAX_LIMIT = 1_000

    def __init__(
        self,
        *,
        connector: URLhausRecentURLsConnector,
        limit: int | None = None,
    ) -> None:
        if connector is None:
            raise ValueError(
                "URLhaus connector must not "
                "be None."
            )

        self._validate_limit(
            limit
        )

        self._connector = connector
        self._limit = limit

    def fetch(
        self,
        *,
        cursor: str | None,
        state_metadata: (
            dict[str, Any] | None
        ) = None,
    ) -> FetchResult:
        """
        Fetch one complete URLhaus recent-URL window.

        URLhaus recent URLs do not expose an application cursor.
        The response is complete for the requested recent window,
        but it is not a complete historical URLhaus snapshot.
        """

        if cursor is not None:
            raise ValueError(
                "URLhaus recent URL collection "
                "does not support cursors."
            )

        # URLhaus currently provides no conditional state for this
        # endpoint. The object is deliberately not modified.
        del state_metadata

        response = (
            self._connector
            .fetch_recent_urls(
                limit=self._limit
            )
        )

        query_status, raw_records = (
            self._extract_response_records(
                response
            )
        )

        source_url = (
            self._validate_source_url(
                self._connector
                .canonical_source_url
            )
        )

        fetched_at = datetime.now(
            UTC
        )

        records: list[
            FetchedRecord
        ] = []

        seen_identifiers: set[
            str
        ] = set()

        for index, raw_record in enumerate(
            raw_records
        ):
            if not isinstance(
                raw_record,
                dict,
            ):
                raise ValueError(
                    "Invalid URLhaus record "
                    f"at index {index}: "
                    "expected an object."
                )

            external_record_id = (
                self._extract_urlhaus_id(
                    raw_record,
                    index=index,
                )
            )

            if (
                external_record_id
                in seen_identifiers
            ):
                raise ValueError(
                    "Invalid URLhaus response: "
                    "duplicate URLhaus identifier."
                )

            records.append(
                FetchedRecord(
                    external_record_id=(
                        external_record_id
                    ),
                    payload=raw_record,
                    source_url=source_url,
                    fetched_at=fetched_at,
                    http_status=200,
                )
            )

            seen_identifiers.add(
                external_record_id
            )

        metadata = {
            "source": self.SOURCE_NAME,
            "source_url": source_url,
            "collection_mode": (
                self.COLLECTION_MODE
            ),
            "configured_limit": (
                self._limit
            ),
            "records_count": len(
                records
            ),
            "query_status": (
                query_status
            ),
            # The endpoint has no pagination cursor.
            "pagination_complete": True,
            # Complete for the returned recent window.
            "window_complete": True,
            # It is not a historical full snapshot.
            "historical_complete": False,
        }

        return FetchResult(
            records=tuple(
                records
            ),
            next_cursor=None,
            metadata=metadata,
            connector_version=(
                self.VERSION
            ),
        )

    @staticmethod
    def _extract_response_records(
        response: object,
    ) -> tuple[
        str,
        list[Any],
    ]:
        if not isinstance(
            response,
            dict,
        ):
            raise TypeError(
                "URLhaus response must be "
                "a dictionary."
            )

        query_status = response.get(
            "query_status"
        )

        if query_status == "no_results":
            return (
                "no_results",
                [],
            )

        if query_status != "ok":
            raise ValueError(
                "URLhaus response must have "
                "query_status 'ok' or "
                "'no_results'."
            )

        raw_records = response.get(
            "urls"
        )

        if not isinstance(
            raw_records,
            list,
        ):
            raise ValueError(
                "URLhaus response field "
                "'urls' must be a list."
            )

        return (
            "ok",
            raw_records,
        )

    @staticmethod
    def _extract_urlhaus_id(
        raw_record: dict[str, Any],
        *,
        index: int,
    ) -> str:
        value = raw_record.get(
            "id"
        )

        if isinstance(
            value,
            bool,
        ):
            raise ValueError(
                "Invalid URLhaus record "
                f"at index {index}: "
                "id must be a positive integer."
            )

        if isinstance(
            value,
            int,
        ):
            parsed_value = value

        elif isinstance(
            value,
            str,
        ):
            normalized_value = (
                value.strip()
            )

            if (
                not normalized_value
                or not normalized_value.isascii()
                or not normalized_value.isdigit()
            ):
                raise ValueError(
                    "Invalid URLhaus record "
                    f"at index {index}: "
                    "id must be a positive integer."
                )

            parsed_value = int(
                normalized_value
            )

        else:
            raise ValueError(
                "Invalid URLhaus record "
                f"at index {index}: "
                "id must be a positive integer."
            )

        if parsed_value <= 0:
            raise ValueError(
                "Invalid URLhaus record "
                f"at index {index}: "
                "id must be a positive integer."
            )

        return str(
            parsed_value
        )

    @classmethod
    def _validate_limit(
        cls,
        value: int | None,
    ) -> None:
        if value is None:
            return

        if (
            isinstance(value, bool)
            or not isinstance(
                value,
                int,
            )
        ):
            raise TypeError(
                "limit must be an integer "
                "or None."
            )

        if not (
            1
            <= value
            <= cls.MAX_LIMIT
        ):
            raise ValueError(
                "limit must be between "
                f"1 and {cls.MAX_LIMIT}."
            )

    @staticmethod
    def _validate_source_url(
        value: object,
    ) -> str:
        if not isinstance(
            value,
            str,
        ):
            raise TypeError(
                "URLhaus canonical source URL "
                "must be a string."
            )

        normalized_value = (
            value.strip().rstrip("/")
        )

        parsed_url = urlsplit(
            normalized_value
        )

        if (
            parsed_url.scheme
            not in {
                "http",
                "https",
            }
            or not parsed_url.hostname
        ):
            raise ValueError(
                "URLhaus canonical source URL "
                "must be a valid HTTP URL."
            )

        if (
            parsed_url.username is not None
            or parsed_url.password is not None
            or parsed_url.query
            or parsed_url.fragment
        ):
            raise ValueError(
                "URLhaus canonical source URL "
                "must not contain credentials, "
                "query parameters or fragments."
            )

        return normalized_value