from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol
from uuid import UUID


@dataclass(frozen=True, slots=True)
class SyncStateData:
    source_id: UUID
    cursor: str | None = None
    last_success_at: datetime | None = None
    last_attempt_at: datetime | None = None
    metadata: dict[str, Any] | None = None


class SyncStateRepository(Protocol):
    def get_by_source_id(
        self,
        source_id: UUID,
    ) -> SyncStateData | None:
        ...

    def upsert(
        self,
        state: SyncStateData,
    ) -> None:
        ...

    def mark_attempt(
        self,
        *,
        source_id: UUID,
        attempted_at: datetime,
    ) -> None:
        ...