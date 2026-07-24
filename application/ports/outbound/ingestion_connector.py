from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol, Sequence


@dataclass(frozen=True, slots=True)
class FetchedRecord:
    external_record_id: str
    payload: dict[str, Any]

    source_url: str | None = None
    fetched_at: datetime | None = None
    http_status: int | None = None


@dataclass(frozen=True, slots=True)
class FetchResult:
    records: Sequence[FetchedRecord]

    next_cursor: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    connector_version: str | None = None


class IngestionConnector(Protocol):
    def fetch(
        self,
        *,
        cursor: str | None,
    ) -> FetchResult:
        """Récupère une page ou un lot de données depuis une source."""
        ...