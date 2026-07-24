from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID


@dataclass(frozen=True, slots=True)
class IngestionRunData:
    source_id: UUID
    status: str

    started_at: datetime | None = None
    finished_at: datetime | None = None
    records_received: int = 0
    records_succeeded: int = 0
    records_failed: int = 0
    error_summary: str | None = None
    connector_version: str | None = None


class IngestionRunRepository(Protocol):
    def create(
        self,
        run: IngestionRunData,
    ) -> UUID:
        """Crée une exécution d’ingestion."""
        ...

    def mark_completed(
        self,
        *,
        run_id: UUID,
        finished_at: datetime,
        records_received: int,
        records_succeeded: int,
        records_failed: int,
    ) -> bool:
        """Marque une exécution comme terminée."""
        ...

    def mark_failed(
        self,
        *,
        run_id: UUID,
        finished_at: datetime,
        error_summary: str,
        records_received: int = 0,
        records_succeeded: int = 0,
        records_failed: int = 0,
    ) -> bool:
        """Marque une exécution comme échouée."""
        ...