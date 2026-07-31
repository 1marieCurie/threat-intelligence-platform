from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, Sequence
from uuid import UUID


@dataclass(
    frozen=True,
    slots=True,
)
class IngestionRunPayloadLink:
    """
    Association entre un run d'ingestion et un payload observé.
    """

    ingestion_run_id: UUID
    raw_payload_id: UUID
    observed_at: datetime | None = None


@dataclass(
    frozen=True,
    slots=True,
)
class IngestionRunPayloadBatchResult:
    """
    Résultat d'une création groupée d'associations.
    """

    submitted_count: int
    unique_count: int
    inserted_count: int

    @property
    def duplicate_count(
        self,
    ) -> int:
        return (
            self.submitted_count
            - self.unique_count
        )

    @property
    def existing_count(
        self,
    ) -> int:
        return (
            self.unique_count
            - self.inserted_count
        )

    @property
    def skipped_count(
        self,
    ) -> int:
        return (
            self.submitted_count
            - self.inserted_count
        )


class IngestionRunPayloadRepository(
    Protocol
):
    def link_many_ignore_existing(
        self,
        links: Sequence[
            IngestionRunPayloadLink
        ],
    ) -> IngestionRunPayloadBatchResult:
        """
        Rattache plusieurs payloads à leurs runs.

        Une association déjà existante est ignorée sans erreur.
        """
        ...