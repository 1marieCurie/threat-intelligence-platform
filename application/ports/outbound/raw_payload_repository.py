from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol, Sequence
from uuid import UUID


@dataclass(frozen=True, slots=True)
class RawPayloadData:
    source_id: UUID
    ingestion_run_id: UUID
    payload: dict[str, Any]
    payload_hash: str

    external_record_id: str | None = None
    retrieved_at: datetime | None = None
    request_url: str | None = None
    http_status: int | None = None
    source_updated_at: datetime | None = None
    processing_status: str = "pending"
    error_message: str | None = None


@dataclass(frozen=True, slots=True)
class PersistedRawPayload:
    id: UUID
    source_id: UUID
    ingestion_run_id: UUID
    payload: dict[str, Any]
    payload_hash: str
    retrieved_at: datetime
    processing_status: str

    external_record_id: str | None = None
    request_url: str | None = None
    http_status: int | None = None
    source_updated_at: datetime | None = None
    error_message: str | None = None


class RawPayloadRepository(Protocol):
    def save(
        self,
        payload: RawPayloadData,
    ) -> UUID:
        """Persiste un payload brut et retourne son identifiant."""
        ...

    def exists_by_identity(
        self,
        *,
        source_id: UUID,
        external_record_id: str | None,
        payload_hash: str,
    ) -> bool:
        """Vérifie si cette version du payload existe déjà."""
        ...

    
    def claim_pending(
        self,
        *,
        source_id: UUID,
        limit: int,
    ) -> Sequence[PersistedRawPayload]:
        """
        Réserve atomiquement un lot de payloads en attente.

        Les payloads retournés sont immédiatement marqués
        comme processing dans la transaction courante.
        """
        ...
        
        
    def mark_processed(
        self,
        *,
        payload_id: UUID,
    ) -> bool:
        """Marque un payload comme traité avec succès."""
        ...

    def mark_failed(
        self,
        *,
        payload_id: UUID,
        error_message: str,
    ) -> bool:
        """Marque un payload comme échoué avec une erreur assainie."""
        ...